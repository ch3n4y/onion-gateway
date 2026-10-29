package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

const sessionCookie = "og_session"

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

type Config struct {
	Addr             string
	DataDir          string
	PasswordHash     string
	SessionKey       []byte
	SessionTTL       time.Duration
	SecureCookie     bool
	TorControlAddr   string
	TorCookiePath    string
	CaddyAdminURL    string
	CaddyAdminListen string
	OnionServeAddr   string
	OnionTarget      string
	OnionVirtualPort string
	VanityWorkers    int
}

func env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func loadConfig() (Config, error) {
	cfg := Config{
		Addr:             env("PANEL_ADDR", ":8000"),
		DataDir:          env("DATA_DIR", "/data"),
		TorControlAddr:   env("TOR_CONTROL_ADDR", "tor:9051"),
		TorCookiePath:    env("TOR_COOKIE_PATH", "/tor-data/control_auth_cookie"),
		CaddyAdminURL:    env("CADDY_ADMIN_URL", "http://caddy:2019"),
		CaddyAdminListen: env("CADDY_ADMIN_LISTEN", "0.0.0.0:2019"),
		OnionServeAddr:   env("CADDY_SERVE_ADDR", ":8080"),
		OnionTarget:      env("ONION_TARGET", "caddy:8080"),
		OnionVirtualPort: env("ONION_VIRTUAL_PORT", "80"),
		SessionTTL:       12 * time.Hour,
	}
	if w, err := strconv.Atoi(env("VANITY_WORKERS", "0")); err == nil {
		cfg.VanityWorkers = w
	}

	switch {
	case strings.TrimSpace(os.Getenv("PANEL_PASSWORD_HASH")) != "":
		cfg.PasswordHash = strings.TrimSpace(os.Getenv("PANEL_PASSWORD_HASH"))
	case strings.TrimSpace(os.Getenv("PANEL_PASSWORD")) != "":
		h, err := bcrypt.GenerateFromPassword([]byte(os.Getenv("PANEL_PASSWORD")), bcrypt.DefaultCost)
		if err != nil {
			return cfg, err
		}
		cfg.PasswordHash = string(h)
	default:
		return cfg, errors.New("set PANEL_PASSWORD (plaintext, hashed at boot) or PANEL_PASSWORD_HASH")
	}

	if k := env("SESSION_KEY", ""); k != "" {
		raw, err := hex.DecodeString(k)
		if err != nil || len(raw) < 16 {
			return cfg, errors.New("SESSION_KEY must be >=16 bytes of hex")
		}
		cfg.SessionKey = raw
	} else {
		// Random per boot: sessions do not survive a restart, which is fine for a
		// single-operator panel but worth knowing.
		cfg.SessionKey = make([]byte, 32)
		if _, err := rand.Read(cfg.SessionKey); err != nil {
			return cfg, err
		}
		log.Print("SESSION_KEY unset: sessions will not survive a restart")
	}
	return cfg, nil
}

type App struct {
	cfg    Config
	store  *Store
	tor    *TorClient
	caddy  *CaddyClient
	vanity *VanityManager

	mu     sync.Mutex
	active map[string]string // service ID -> published onion ID

	loginMu sync.Mutex
	fails   map[string][]time.Time
}

func main() {
	gin.SetMode(gin.ReleaseMode)
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	store, err := NewStore(cfg.DataDir)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	app := &App{
		cfg:    cfg,
		store:  store,
		tor:    NewTorClient(cfg.TorControlAddr, cfg.TorCookiePath),
		caddy:  NewCaddyClient(cfg.CaddyAdminURL, cfg.CaddyAdminListen, cfg.OnionServeAddr),
		vanity: NewVanityManager(cfg.VanityWorkers),
		active: map[string]string{},
		fails:  map[string][]time.Time{},
	}

	go app.syncLoop(context.Background())

	srv := &http.Server{Addr: cfg.Addr, Handler: app.router()}
	log.Printf("onion-gateway API on %s (tor %s, caddy %s)", cfg.Addr, cfg.TorControlAddr, cfg.CaddyAdminURL)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

// syncLoop keeps tor and caddy converged with stored state. It also covers the
// case where tor restarts and silently forgets every detached onion service.
func (a *App) syncLoop(ctx context.Context) {
	time.Sleep(2 * time.Second)
	for {
		if err := a.reconcile(ctx); err != nil {
			log.Printf("sync: %v", err)
		}
		time.Sleep(30 * time.Second)
	}
}

func (a *App) reconcile(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.reconcileLocked(ctx)
}

func (a *App) reconcileLocked(ctx context.Context) error {
	addrs := map[string]Address{}
	for _, ad := range a.store.ListAddresses() {
		addrs[ad.ID] = ad
	}

	desired := map[string]Address{} // service ID -> address to publish
	for _, s := range a.store.ListServices() {
		ad, ok := addrs[s.AddressID]
		if !ok || !s.Enabled {
			continue
		}
		desired[s.ID] = ad
	}

	if _, err := a.tor.Status(ctx); err != nil {
		// Tor is unreachable from here (down or restarting). We cannot know what it
		// still holds, so drop our view of the published set and re-assert
		// everything on the next pass. Detached services make the re-assert
		// harmless: they either exist already or get re-created with the same key.
		a.active = map[string]string{}
		_ = a.caddy.Apply(ctx, a.buildRoutes())
		return fmt.Errorf("tor: %w", err)
	}

	// Ask tor what it actually holds. Re-issuing ADD_ONION for a service that is
	// already registered trips a tor 0.4.9 assertion ("private key collides") that
	// can drop the service, so existing ones are adopted instead. Anything we
	// believe is published but tor does not list (tor restarted and lost its
	// in-memory services) is forgotten so the loop below re-creates it.
	published := map[string]bool{}
	if ids, err := a.tor.DetachedOnions(ctx); err == nil {
		for _, id := range ids {
			published[id] = true
		}
		for sid, onion := range a.active {
			if !published[onion] {
				delete(a.active, sid)
			}
		}
	}

	var firstErr error
	for sid, onion := range a.active {
		if ad, ok := desired[sid]; ok && ad.OnionID == onion {
			continue
		}
		if err := a.tor.DelOnion(ctx, onion); err != nil && !IsUnknownService(err) {
			log.Printf("del onion %s: %v", onion, err)
			if firstErr == nil {
				firstErr = err
			}
		}
		delete(a.active, sid)
	}

	for sid, ad := range desired {
		if _, ok := a.active[sid]; ok {
			continue
		}
		if ad.OnionID != "" && published[ad.OnionID] {
			a.active[sid] = ad.OnionID
			continue
		}
		onionID, key, err := a.tor.AddOnion(ctx, ad.PrivKey, a.cfg.OnionVirtualPort, a.cfg.OnionTarget)
		if IsAlreadyInUse(err) && ad.OnionID != "" {
			if !published[ad.OnionID] {
				// tor thinks the key collides yet does not list the service: its
				// in-memory onion map is stale after a collision assertion, and only
				// restarting the tor container clears it.
				log.Printf("WARNING: tor reports %s as a collision but does not list it; restart the tor container", ad.OnionID)
			}
			// Raced with another pass: tor already holds it, same address.
			onionID, key, err = ad.OnionID, ad.PrivKey, nil
		}
		if err != nil {
			log.Printf("publish onion for %q: %v", ad.Label, err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if onionID != ad.OnionID || key != ad.PrivKey {
			ad.OnionID, ad.PrivKey = onionID, key
			if err := a.store.PutAddress(ad); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
		}
		a.active[sid] = onionID
	}

	// Rebuild routes after publishing: a brand-new address only gets its onion ID
	// once tor has actually created it.
	if err := a.caddy.Apply(ctx, a.buildRoutes()); err != nil {
		if firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ---------- views ----------

type addressView struct {
	ID          string    `json:"id"`
	Address     string    `json:"address"`
	Label       string    `json:"label"`
	Source      string    `json:"source"`
	Vanity      string    `json:"vanity"`
	ServiceID   string    `json:"service_id,omitempty"`
	ServiceName string    `json:"service_name,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

type serviceView struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	AddressID string    `json:"address_id"`
	Address   string    `json:"address"`
	Target    string    `json:"target"`
	BasicUser string    `json:"basic_user"`
	RateLimit int       `json:"rate_limit"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

func onionName(id string) string {
	if id == "" {
		return ""
	}
	return id + ".onion"
}

func addressViews(a *App) []addressView {
	svcs := a.store.ListServices()
	bound := map[string]Service{}
	for _, s := range svcs {
		if s.AddressID != "" {
			bound[s.AddressID] = s
		}
	}
	out := []addressView{}
	for _, ad := range a.store.ListAddresses() {
		v := addressView{
			ID: ad.ID, Address: onionName(ad.OnionID), Label: ad.Label,
			Source: ad.Source, Vanity: ad.Vanity, CreatedAt: ad.CreatedAt,
		}
		if s, ok := bound[ad.ID]; ok {
			v.ServiceID, v.ServiceName = s.ID, s.Name
		}
		out = append(out, v)
	}
	return out
}

func serviceViews(a *App) []serviceView {
	addrs := map[string]Address{}
	for _, ad := range a.store.ListAddresses() {
		addrs[ad.ID] = ad
	}
	out := []serviceView{}
	for _, s := range a.store.ListServices() {
		v := serviceView{
			ID: s.ID, Name: s.Name, AddressID: s.AddressID, Target: s.Target,
			BasicUser: s.BasicUser, RateLimit: s.RateLimit, Enabled: s.Enabled, CreatedAt: s.CreatedAt,
		}
		if ad, ok := addrs[s.AddressID]; ok {
			v.Address = onionName(ad.OnionID)
		}
		out = append(out, v)
	}
	return out
}

// ---------- validation ----------

var (
	targetRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,252}:\d{1,5}$`)
	userRe   = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)
)

type serviceReq struct {
	Name      string `json:"name"`
	Target    string `json:"target"`
	BasicUser string `json:"basic_user"`
	BasicPass string `json:"basic_pass"`
	RateLimit int    `json:"rate_limit"`
	AddressID string `json:"address_id"`
}

func (r serviceReq) validate() error {
	if strings.TrimSpace(r.Name) == "" || len(r.Name) > 60 {
		return errors.New("名称必填，最多 60 字符")
	}
	if !targetRe.MatchString(r.Target) {
		return errors.New("目标格式应为 host:port，例如 10.0.0.10:8080")
	}
	if i := strings.LastIndex(r.Target, ":"); i > 0 {
		port, err := strconv.Atoi(r.Target[i+1:])
		if err != nil || port < 1 || port > 65535 {
			return errors.New("目标端口需在 1-65535 之间")
		}
	}
	if r.BasicUser != "" && !userRe.MatchString(r.BasicUser) {
		return errors.New("Basic Auth 用户名含非法字符")
	}
	if r.BasicUser != "" && r.BasicPass == "" {
		return errors.New("设置 Basic Auth 需要同时给用户名和密码")
	}
	if r.RateLimit < 0 || r.RateLimit > 100000 {
		return errors.New("限速需在 0-100000 之间")
	}
	return nil
}

// ---------- HTTP layer ----------

func (a *App) router() *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())

	api := r.Group("/api")
	api.GET("/session", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"authenticated": a.checkSession(c)})
	})
	api.POST("/login", a.login)

	auth := api.Group("", a.authRequired())
	auth.POST("/logout", a.logout)
	auth.GET("/status", a.status)
	auth.POST("/probe", a.probe)

	auth.GET("/services", a.listServices)
	auth.POST("/services", a.createService)
	auth.PATCH("/services/:id", a.updateService)
	auth.DELETE("/services/:id", a.deleteService)

	auth.GET("/addresses", a.listAddresses)
	auth.PATCH("/addresses/:id", a.updateAddress)
	auth.DELETE("/addresses/:id", a.deleteAddress)
	auth.POST("/addresses/:id/unbind", a.unbindAddress)

	auth.GET("/vanity", a.listVanity)
	auth.POST("/vanity", a.startVanity)
	auth.POST("/vanity/:id/stop", a.stopVanity)
	auth.POST("/vanity/:id/adopt", a.adoptVanity)

	r.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
	})
	return r
}

// ---------- auth ----------

func (a *App) sign(exp time.Time) string {
	payload := strconv.FormatInt(exp.Unix(), 10)
	mac := hmac.New(sha256.New, a.cfg.SessionKey)
	mac.Write([]byte(payload))
	return payload + "." + hex.EncodeToString(mac.Sum(nil))
}

func (a *App) valid(token string) bool {
	payload, sig, ok := strings.Cut(token, ".")
	if !ok {
		return false
	}
	mac := hmac.New(sha256.New, a.cfg.SessionKey)
	mac.Write([]byte(payload))
	want := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return false
	}
	exp, err := strconv.ParseInt(payload, 10, 64)
	if err != nil {
		return false
	}
	return time.Now().Unix() < exp
}

func (a *App) checkSession(c *gin.Context) bool {
	tok, err := c.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	return a.valid(tok)
}

func (a *App) authRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !a.checkSession(c) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "login required"})
			return
		}
		c.Next()
	}
}

// loginThrottled allows 5 failures per minute per client IP.
func (a *App) loginThrottled(ip string) bool {
	a.loginMu.Lock()
	defer a.loginMu.Unlock()
	cutoff := time.Now().Add(-time.Minute)
	kept := a.fails[ip][:0]
	for _, t := range a.fails[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	a.fails[ip] = kept
	return len(kept) < 5
}

func (a *App) recordFailure(ip string) {
	a.loginMu.Lock()
	defer a.loginMu.Unlock()
	a.fails[ip] = append(a.fails[ip], time.Now())
}

func (a *App) login(c *gin.Context) {
	var req struct {
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	ip := c.ClientIP()
	if !a.loginThrottled(ip) {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "尝试过于频繁，请等一分钟"})
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(a.cfg.PasswordHash), []byte(req.Password)) != nil {
		a.recordFailure(ip)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "密码错误"})
		return
	}
	exp := time.Now().Add(a.cfg.SessionTTL)
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     sessionCookie,
		Value:    a.sign(exp),
		Path:     "/",
		HttpOnly: true,
		Secure:   a.cfg.SecureCookie,
		SameSite: http.SameSiteStrictMode,
		Expires:  exp,
	})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func (a *App) logout(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
	})
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ---------- status / probe ----------

func (a *App) status(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 8*time.Second)
	defer cancel()
	torSt, torErr := a.tor.Status(ctx)
	caddyErr := a.caddy.Status(ctx)
	out := gin.H{"version": version, "tor_ok": torErr == nil, "caddy_ok": caddyErr == nil}
	if torErr == nil {
		out["tor_version"] = torSt.Version
		out["tor_bootstrap"] = torSt.Bootstrap
		out["tor_phase"] = torSt.Phase
		if ids, err := a.tor.DetachedOnions(ctx); err == nil {
			out["tor_services"] = len(ids)
		}
	} else {
		out["tor_error"] = torErr.Error()
	}
	if caddyErr != nil {
		out["caddy_error"] = caddyErr.Error()
	}
	c.JSON(http.StatusOK, out)
}

// probe answers "is this target actually reachable from the proxy container?" so
// a typo in host or port is caught while typing instead of after publishing.
func (a *App) probe(c *gin.Context) {
	var req struct {
		Target string `json:"target"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	target := strings.TrimSpace(req.Target)
	if !targetRe.MatchString(target) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target must be host:port"})
		return
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", target, 3*time.Second)
	ms := time.Since(start).Milliseconds()
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"ok": false, "ms": ms, "error": err.Error()})
		return
	}
	_ = conn.Close()
	c.JSON(http.StatusOK, gin.H{"ok": true, "ms": ms})
}

// ---------- services ----------

func (a *App) listServices(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"services": serviceViews(a), "addresses": addressViews(a)})
}

func (a *App) createService(c *gin.Context) {
	var req serviceReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if err := req.validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var addressID string
	if req.AddressID != "" {
		ad, ok := a.store.GetAddress(req.AddressID)
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{"error": "地址不存在"})
			return
		}
		if svc, bound := a.store.ServiceUsingAddress(ad.ID); bound {
			c.JSON(http.StatusConflict, gin.H{"error": "该地址已绑定到服务 " + svc.Name})
			return
		}
		addressID = ad.ID
	} else {
		ad := Address{ID: newID(), Label: req.Name, Source: "service", CreatedAt: time.Now().UTC()}
		if err := a.store.PutAddress(ad); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		addressID = ad.ID
	}

	svc := Service{
		ID:        newID(),
		Name:      req.Name,
		AddressID: addressID,
		Target:    req.Target,
		RateLimit: req.RateLimit,
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
	}
	if req.BasicUser != "" {
		h, err := bcrypt.GenerateFromPassword([]byte(req.BasicPass), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "hash failed"})
			return
		}
		svc.BasicUser, svc.BasicHash = req.BasicUser, string(h)
	}
	if err := a.store.PutService(svc); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	warn := ""
	if err := a.reconcile(c.Request.Context()); err != nil {
		warn = err.Error()
	}
	c.JSON(http.StatusCreated, gin.H{"warning": warn, "services": serviceViews(a), "addresses": addressViews(a)})
}

func (a *App) updateService(c *gin.Context) {
	id := c.Param("id")
	cur, ok := a.store.GetService(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	var req struct {
		Name      *string `json:"name"`
		Target    *string `json:"target"`
		BasicUser *string `json:"basic_user"`
		BasicPass *string `json:"basic_pass"`
		RateLimit *int    `json:"rate_limit"`
		Enabled   *bool   `json:"enabled"`
		AddressID *string `json:"address_id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}

	check := serviceReq{Name: cur.Name, Target: cur.Target, RateLimit: cur.RateLimit}
	if req.Name != nil {
		check.Name = strings.TrimSpace(*req.Name)
	}
	if req.Target != nil {
		check.Target = strings.TrimSpace(*req.Target)
	}
	if req.RateLimit != nil {
		check.RateLimit = *req.RateLimit
	}

	// Work out the resulting basic-auth state. "unchanged" as the password means
	// "keep the stored hash", so a plain enabled-toggle never needs a password.
	switch {
	case req.BasicUser != nil && strings.TrimSpace(*req.BasicUser) == "":
		check.BasicUser, check.BasicPass = "", ""
	case req.BasicUser == nil && req.BasicPass == nil:
		check.BasicUser, check.BasicPass = cur.BasicUser, "unchanged"
	case req.BasicPass != nil:
		check.BasicUser = cur.BasicUser
		if req.BasicUser != nil {
			check.BasicUser = strings.TrimSpace(*req.BasicUser)
		}
		check.BasicPass = *req.BasicPass
	default: // user given without a password
		if strings.TrimSpace(*req.BasicUser) != cur.BasicUser {
			c.JSON(http.StatusBadRequest, gin.H{"error": "更换 Basic Auth 用户需要同时给密码"})
			return
		}
		check.BasicUser, check.BasicPass = cur.BasicUser, "unchanged"
	}
	if cur.BasicUser == "" && check.BasicUser == "" {
		check.BasicPass = ""
	}
	if err := check.validate(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.AddressID != nil {
		newID := strings.TrimSpace(*req.AddressID)
		if newID == "" {
			cur.AddressID = ""
		} else if newID != cur.AddressID {
			ad, ok := a.store.GetAddress(newID)
			if !ok {
				c.JSON(http.StatusBadRequest, gin.H{"error": "地址不存在"})
				return
			}
			if svc, bound := a.store.ServiceUsingAddress(ad.ID); bound && svc.ID != cur.ID {
				c.JSON(http.StatusConflict, gin.H{"error": "该地址已绑定到服务 " + svc.Name})
				return
			}
			cur.AddressID = ad.ID
		}
	}

	cur.Name = check.Name
	cur.Target = check.Target
	cur.RateLimit = check.RateLimit
	if req.Enabled != nil {
		cur.Enabled = *req.Enabled
	}
	switch {
	case check.BasicUser == "":
		cur.BasicUser, cur.BasicHash = "", ""
	case req.BasicPass != nil:
		h, err := bcrypt.GenerateFromPassword([]byte(*req.BasicPass), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "hash failed"})
			return
		}
		cur.BasicUser, cur.BasicHash = check.BasicUser, string(h)
	default:
		cur.BasicUser = check.BasicUser
	}

	if err := a.store.PutService(cur); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	warn := ""
	if err := a.reconcile(c.Request.Context()); err != nil {
		warn = err.Error()
	}
	c.JSON(http.StatusOK, gin.H{"warning": warn, "services": serviceViews(a), "addresses": addressViews(a)})
}

// deleteService removes the routing rule only: the address stays in the library
// so it can be bound to something else later.
func (a *App) deleteService(c *gin.Context) {
	id := c.Param("id")
	if _, ok := a.store.GetService(id); !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if err := a.store.DeleteService(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	warn := ""
	if err := a.reconcile(c.Request.Context()); err != nil {
		warn = err.Error()
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "warning": warn, "services": serviceViews(a), "addresses": addressViews(a)})
}

// ---------- addresses ----------

func (a *App) listAddresses(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"addresses": addressViews(a), "services": serviceViews(a)})
}

func (a *App) updateAddress(c *gin.Context) {
	id := c.Param("id")
	ad, ok := a.store.GetAddress(id)
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	var req struct {
		Label *string `json:"label"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	if req.Label != nil {
		label := strings.TrimSpace(*req.Label)
		if len(label) > 60 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "标签最多 60 字符"})
			return
		}
		ad.Label = label
	}
	if err := a.store.PutAddress(ad); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"addresses": addressViews(a)})
}

func (a *App) deleteAddress(c *gin.Context) {
	id := c.Param("id")
	if _, ok := a.store.GetAddress(id); !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	if svc, bound := a.store.ServiceUsingAddress(id); bound {
		c.JSON(http.StatusConflict, gin.H{"error": "先解绑：该地址正被服务 " + svc.Name + " 使用"})
		return
	}
	if err := a.store.DeleteAddress(id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "addresses": addressViews(a)})
}

func (a *App) unbindAddress(c *gin.Context) {
	id := c.Param("id")
	svc, bound := a.store.ServiceUsingAddress(id)
	if !bound {
		c.JSON(http.StatusOK, gin.H{"ok": true, "addresses": addressViews(a), "services": serviceViews(a)})
		return
	}
	svc.AddressID = ""
	if err := a.store.PutService(svc); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	warn := ""
	if err := a.reconcile(c.Request.Context()); err != nil {
		warn = err.Error()
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "warning": warn, "addresses": addressViews(a), "services": serviceViews(a)})
}

// ---------- vanity ----------

type vanityFound struct {
	OnionID string    `json:"onion_id"`
	FoundAt time.Time `json:"found_at"`
	Tested  uint64    `json:"tested"`
}

type vanityView struct {
	ID       string        `json:"id"`
	Prefix   string        `json:"prefix"`
	State    string        `json:"state"`
	Want     int           `json:"want"`
	Workers  int           `json:"workers"`
	Tested   uint64        `json:"tested"`
	Speed    float64       `json:"speed"`
	ETA      float64       `json:"eta"`
	Elapsed  float64       `json:"elapsed"`
	KeySpace float64       `json:"key_space"`
	Found    []vanityFound `json:"found"`
	Started  time.Time     `json:"started_at"`
	Ended    *time.Time    `json:"ended_at,omitempty"`
}

func vanityViews(a *App) []vanityView {
	out := []vanityView{}
	for _, v := range a.vanity.List() {
		found := make([]vanityFound, 0, len(v.Found))
		for _, f := range v.Found {
			found = append(found, vanityFound{OnionID: f.OnionID, FoundAt: f.FoundAt, Tested: f.Tested})
		}
		out = append(out, vanityView{
			ID: v.ID, Prefix: v.Prefix, State: v.State, Want: v.Want, Workers: v.Workers,
			Tested: v.Tested, Speed: v.Speed, ETA: v.ETA, Elapsed: v.Elapsed,
			KeySpace: v.KeySpace, Found: found, Started: v.Started, Ended: v.Ended,
		})
	}
	return out
}

func (a *App) listVanity(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"jobs": vanityViews(a), "workers": defaultVanityWorkers()})
}

func (a *App) startVanity(c *gin.Context) {
	var req struct {
		Prefix string `json:"prefix"`
		Want   int    `json:"want"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	if req.Want == 0 {
		req.Want = 1
	}
	if _, err := a.vanity.Start(req.Prefix, req.Want); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"jobs": vanityViews(a)})
}

func (a *App) stopVanity(c *gin.Context) {
	if !a.vanity.Stop(c.Param("id")) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"jobs": vanityViews(a)})
}

// adoptVanity turns a found result into a library address (not bound to anything).
func (a *App) adoptVanity(c *gin.Context) {
	job, ok := a.vanity.Get(c.Param("id"))
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "job not found"})
		return
	}
	var req struct {
		Index int `json:"index"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	view := jobView(job)
	if req.Index < 0 || req.Index >= len(view.Found) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "结果序号越界"})
		return
	}
	res := view.Found[req.Index]

	// Reject duplicates so the same vanity hit cannot enter the library twice.
	for _, ad := range a.store.ListAddresses() {
		if ad.OnionID == res.OnionID {
			c.JSON(http.StatusConflict, gin.H{"error": "该地址已在地址库中"})
			return
		}
	}

	ad := Address{
		ID:        newID(),
		OnionID:   res.OnionID,
		PrivKey:   res.PrivKey,
		Label:     job.Prefix,
		Source:    "vanity",
		Vanity:    job.Prefix,
		CreatedAt: time.Now().UTC(),
	}
	if err := a.store.PutAddress(ad); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"addresses": addressViews(a), "services": serviceViews(a)})
}
