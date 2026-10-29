package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/bcrypt"
)

// fakeTor implements just enough of the control protocol to exercise TorClient.
type fakeTor struct {
	ln      net.Listener
	mu      sync.Mutex
	added   map[string]string // onionID -> key
	deleted []string
	fail    bool
}

func newFakeTor(t *testing.T) *fakeTor {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeTor{ln: ln, added: map[string]string{}}
	go f.serve()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeTor) addr() string { return f.ln.Addr().String() }

func (f *fakeTor) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

func (f *fakeTor) handle(conn net.Conn) {
	defer conn.Close()
	w := func(s string) { _, _ = conn.Write([]byte(s)) }
	// Tor 0.4.9 does not greet unsolicited: the client must ask first.

	r := bufio.NewReader(conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		f.mu.Lock()
		failing := f.fail
		f.mu.Unlock()
		if failing {
			w("552 boom\r\n")
			continue
		}
		switch {
		case strings.HasPrefix(line, "PROTOCOLINFO"):
			w("250-PROTOCOLINFO 1\r\n250-AUTH METHODS=COOKIE\r\n250-VERSION Tor=\"0.4.8.10\"\r\n250 OK\r\n")
		case strings.HasPrefix(line, "AUTHENTICATE"):
			w("250 OK\r\n")
		case strings.HasPrefix(line, "GETINFO version"):
			w("250-version=0.4.8.10\r\n250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY=\"Done\"\r\n250 OK\r\n")
		case strings.HasPrefix(line, "ADD_ONION"):
			fields := strings.Fields(line)
			key := fields[1]
			newKey := strings.HasPrefix(key, "NEW:")
			if newKey {
				raw := make([]byte, 64)
				_, _ = rand.Read(raw)
				key = "ED25519-V3:" + base64.StdEncoding.EncodeToString(raw)
			}
			sum := sha256.Sum256([]byte(key))
			id := strings.ToLower(base32NoPad(sum[:]))[:56]
			f.mu.Lock()
			_, exists := f.added[id]
			f.added[id] = key
			f.mu.Unlock()
			if !newKey && exists {
				// Real tor 0.4.9 words it this way; the panel must treat it as success.
				w("550 Onion address collision\r\n")
				continue
			}
			if newKey {
				w(fmt.Sprintf("250-ServiceID=%s.onion\r\n250-PrivateKey=%s\r\n250 OK\r\n", id, key))
			} else {
				w(fmt.Sprintf("250-ServiceID=%s.onion\r\n250 OK\r\n", id))
			}
		case strings.HasPrefix(line, "GETINFO onions/detached"):
			f.mu.Lock()
			ids := make([]string, 0, len(f.added))
			for id := range f.added {
				ids = append(ids, id)
			}
			f.mu.Unlock()
			if len(ids) <= 1 {
				// Single value: tor answers on one dash line.
				w(fmt.Sprintf("250-onions/detached=%s\r\n250 OK\r\n", strings.Join(ids, " ")))
			} else {
				// Several values: tor switches to a "+" data block.
				w("250+onions/detached=\r\n")
				for _, id := range ids {
					w(id + "\r\n")
				}
				w(".\r\n250 OK\r\n")
			}
		case strings.HasPrefix(line, "DEL_ONION"):
			fields := strings.Fields(line)
			f.mu.Lock()
			_, exists := f.added[fields[1]]
			delete(f.added, fields[1])
			f.deleted = append(f.deleted, fields[1])
			f.mu.Unlock()
			if !exists {
				w("552 Unknown Onion Service id\r\n")
				continue
			}
			w("250 OK\r\n")
		default:
			w("510 unrecognized\r\n")
		}
	}
}

func base32NoPad(b []byte) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	var sb strings.Builder
	for i := 0; i < len(b); i += 5 {
		chunk := b[i:min(i+5, len(b))]
		var acc uint64
		for j, c := range chunk {
			acc |= uint64(c) << (8 * (4 - j))
		}
		for j := 0; j < 8; j++ {
			sb.WriteByte(alphabet[(acc>>uint(35-5*j))&0x1f])
		}
	}
	return sb.String()
}

// fakeCaddy captures the config the panel pushes.
type fakeCaddy struct {
	mu   sync.Mutex
	last map[string]any
	srv  *httptest.Server
	fail bool
}

func newFakeCaddy(t *testing.T) *fakeCaddy {
	t.Helper()
	f := &fakeCaddy{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		failing := f.fail
		f.mu.Unlock()
		if failing {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		switch {
		case r.URL.Path == "/load" && r.Method == http.MethodPost:
			var cfg map[string]any
			if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			f.mu.Lock()
			f.last = cfg
			f.mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case r.URL.Path == "/config/":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{}"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCaddy) routes(t *testing.T) []any {
	t.Helper()
	f.mu.Lock()
	cfg := f.last
	f.mu.Unlock()
	if cfg == nil {
		return nil
	}
	return cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["srv0"].(map[string]any)["routes"].([]any)
}

type harness struct {
	app   *App
	tor   *fakeTor
	caddy *fakeCaddy
	ts    *httptest.Server
	pass  string
	dir   string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	cookie := filepath.Join(dir, "control_auth_cookie")
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if err := os.WriteFile(cookie, raw, 0o600); err != nil {
		t.Fatalf("cookie: %v", err)
	}

	ft := newFakeTor(t)
	fc := newFakeCaddy(t)
	pass := "s3cret-pass"
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	store, err := NewStore(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	cfg := Config{
		DataDir:          filepath.Join(dir, "data"),
		PasswordHash:     string(hash),
		SessionKey:       []byte("0123456789abcdef0123456789abcdef"),
		SessionTTL:       time.Hour,
		TorControlAddr:   ft.addr(),
		TorCookiePath:    cookie,
		CaddyAdminURL:    fc.srv.URL,
		CaddyAdminListen: "0.0.0.0:2019",
		OnionServeAddr:   ":8080",
		OnionTarget:      "caddy:8080",
		OnionVirtualPort: "80",
		VanityWorkers:    2,
	}
	h := &harness{
		tor:   ft,
		caddy: fc,
		pass:  pass,
		dir:   dir,
		app: &App{
			cfg:    cfg,
			store:  store,
			tor:    NewTorClient(cfg.TorControlAddr, cfg.TorCookiePath),
			caddy:  NewCaddyClient(cfg.CaddyAdminURL, cfg.CaddyAdminListen, cfg.OnionServeAddr),
			vanity: NewVanityManager(cfg.VanityWorkers),
			active: map[string]string{},
			fails:  map[string][]time.Time{},
		},
	}
	h.ts = httptest.NewServer(h.app.router())
	t.Cleanup(h.ts.Close)
	return h
}

func (h *harness) do(t *testing.T, method, path string, body any, cookie *http.Cookie) (*http.Response, map[string]any) {
	t.Helper()
	var rd *strings.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		rd = strings.NewReader(string(buf))
	} else {
		rd = strings.NewReader("")
	}
	req, err := http.NewRequest(method, h.ts.URL+path, rd)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	return resp, out
}

func (h *harness) login(t *testing.T) *http.Cookie {
	t.Helper()
	resp, _ := h.do(t, http.MethodPost, "/api/login", map[string]string{"password": h.pass}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == sessionCookie {
			return c
		}
	}
	t.Fatal("no session cookie")
	return nil
}

func listOf(m map[string]any, key string) []any {
	v, _ := m[key].([]any)
	return v
}

func (h *harness) published(t *testing.T) int {
	t.Helper()
	h.tor.mu.Lock()
	defer h.tor.mu.Unlock()
	return len(h.tor.added)
}

// ---------- tests ----------

func TestOnionAddressMatchesTor(t *testing.T) {
	// A real onion identity produced by tor itself: pins both the address
	// derivation and the expanded-key layout the vanity search must emit.
	const onionID = "qoaf2t5cucwprcsclbvnykhryhuusqv3kaewwdpsm4tbm2yasb6567yd"
	const blob = "ED25519-V3:GCtNsvX7i/huHJz4mH8RW+vVIcmTMSp1lPzieUfpyWJJgG4MrFUqvEY/ft7xQYgzzqg9spu/Sx2YoI5bdHYo0g=="

	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(blob, "ED25519-V3:"))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(raw) != 64 {
		t.Fatalf("expanded key is %d bytes, want 64", len(raw))
	}
	scalar, err := new(edwards25519.Scalar).SetBytesWithClamping(raw[:32])
	if err != nil {
		t.Fatalf("scalar: %v", err)
	}
	pub := new(edwards25519.Point).ScalarBaseMult(scalar).Bytes()
	if got := onionAddress(pub); got != onionID {
		t.Fatalf("derived %q, tor says %q", got, onionID)
	}
	if torKeyBlob(raw) != blob {
		t.Fatal("key blob round-trip mismatch")
	}

	// A freshly minted identity must be self-consistent too.
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand: %v", err)
	}
	exp, id, err := newOnionIdentity(seed)
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	if len(exp) != 64 || len(id) != 56 {
		t.Fatalf("bad identity: %d bytes, id %q", len(exp), id)
	}
	if strings.ToLower(id) != id {
		t.Fatalf("address must be lowercase: %q", id)
	}
	sc, err := new(edwards25519.Scalar).SetBytesWithClamping(exp[:32])
	if err != nil {
		t.Fatalf("scalar: %v", err)
	}
	if got := onionAddress(new(edwards25519.Point).ScalarBaseMult(sc).Bytes()); got != id {
		t.Fatalf("identity not reproducible: %q != %q", got, id)
	}
}

func TestLegacyMigration(t *testing.T) {
	dir := t.TempDir()
	legacy := `{"services":[{"id":"s1","name":"demo","onion_id":"qoaf2t5cucwprcsclbvnykhryhuusqv3kaewwdpsm4tbm2yasb6567yd","priv_key":"ED25519-V3:GCtNsvX7i/huHJz4mH8RW+vVIcmTMSp1lPzieUfpyWJJgG4MrFUqvEY/ft7xQYgzzqg9spu/Sx2YoI5bdHYo0g==","target":"10.0.0.10:8080","enabled":true,"created_at":"2026-10-29T11:05:04Z"}]}`
	if err := os.WriteFile(filepath.Join(dir, "services.json"), []byte(legacy), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	st, err := NewStore(dir)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	svcs := st.ListServices()
	addrs := st.ListAddresses()
	if len(svcs) != 1 || len(addrs) != 1 {
		t.Fatalf("got %d services / %d addresses", len(svcs), len(addrs))
	}
	if svcs[0].AddressID != addrs[0].ID {
		t.Fatal("legacy service was not linked to the new address")
	}
	if addrs[0].OnionID != "qoaf2t5cucwprcsclbvnykhryhuusqv3kaewwdpsm4tbm2yasb6567yd" {
		t.Fatalf("onion id lost: %q", addrs[0].OnionID)
	}
	if addrs[0].Source != "legacy" {
		t.Fatalf("source = %q", addrs[0].Source)
	}
}

func TestAuthGate(t *testing.T) {
	h := newHarness(t)
	if resp, _ := h.do(t, http.MethodGet, "/api/services", nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
	if resp, _ := h.do(t, http.MethodPost, "/api/login", map[string]string{"password": "wrong"}, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong password, got %d", resp.StatusCode)
	}

	h2 := newHarness(t)
	last := 0
	for i := 0; i < 6; i++ {
		resp, _ := h2.do(t, http.MethodPost, "/api/login", map[string]string{"password": "nope"}, nil)
		last = resp.StatusCode
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after 5 failures, got %d", last)
	}
}

func TestCreateServicePublishesAndRoutes(t *testing.T) {
	h := newHarness(t)
	cookie := h.login(t)

	resp, body := h.do(t, http.MethodPost, "/api/services", map[string]any{
		"name": "wiki", "target": "10.0.0.10:8080",
		"basic_user": "alice", "basic_pass": "hunter2", "rate_limit": 120,
	}, cookie)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status %d body %v", resp.StatusCode, body)
	}
	if body["warning"] != "" {
		t.Fatalf("unexpected warning %v", body["warning"])
	}
	svcs := listOf(body, "services")
	addrs := listOf(body, "addresses")
	if len(svcs) != 1 || len(addrs) != 1 {
		t.Fatalf("services=%d addresses=%d", len(svcs), len(addrs))
	}
	svc := svcs[0].(map[string]any)
	addr := svc["address"].(string)
	if !strings.HasSuffix(addr, ".onion") || len(strings.TrimSuffix(addr, ".onion")) != 56 {
		t.Fatalf("bad onion address %q", addr)
	}
	if strings.Contains(fmt.Sprint(body), "ED25519") {
		t.Fatal("private key leaked in response")
	}
	if got := h.published(t); got != 1 {
		t.Fatalf("expected 1 published onion, got %d", got)
	}

	routes := h.caddy.routes(t)
	if len(routes) != 2 {
		t.Fatalf("expected 1 route + 404 fallback, got %d", len(routes))
	}
	route := routes[0].(map[string]any)
	host := route["match"].([]any)[0].(map[string]any)["host"].([]any)[0].(string)
	if host != addr {
		t.Fatalf("host matcher %q != %q", host, addr)
	}
	handlers := route["handle"].([]any)
	if len(handlers) != 3 {
		t.Fatalf("expected rate_limit + auth + proxy, got %d", len(handlers))
	}
	acct := handlers[1].(map[string]any)["providers"].(map[string]any)["http_basic"].(map[string]any)["accounts"].([]any)[0].(map[string]any)
	if acct["username"] != "alice" || !strings.HasPrefix(acct["password"].(string), "$2") {
		t.Fatalf("bad account %v", acct)
	}
}

// The point of the address library: deleting a service must not lose the onion.
func TestDeleteServiceKeepsAddressAndRebind(t *testing.T) {
	h := newHarness(t)
	cookie := h.login(t)

	_, body := h.do(t, http.MethodPost, "/api/services", map[string]any{"name": "wiki", "target": "svc:80"}, cookie)
	svc := listOf(body, "services")[0].(map[string]any)
	addr := listOf(body, "addresses")[0].(map[string]any)
	onion := addr["address"].(string)

	if resp, _ := h.do(t, http.MethodDelete, "/api/services/"+svc["id"].(string), nil, cookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("delete status %d", resp.StatusCode)
	}
	_, body = h.do(t, http.MethodGet, "/api/addresses", nil, cookie)
	if got := len(listOf(body, "services")); got != 0 {
		t.Fatalf("services left: %d", got)
	}
	addrs := listOf(body, "addresses")
	if len(addrs) != 1 {
		t.Fatalf("address lost after service delete: %d", len(addrs))
	}
	kept := addrs[0].(map[string]any)
	if kept["address"] != onion {
		t.Fatalf("address changed: %v != %v", kept["address"], onion)
	}
	if kept["service_id"] != nil {
		t.Fatalf("address still bound: %v", kept["service_id"])
	}
	if got := h.published(t); got != 0 {
		t.Fatalf("unbound address should not stay published, got %d", got)
	}

	// Reuse the kept address for a brand new service.
	resp, body := h.do(t, http.MethodPost, "/api/services", map[string]any{
		"name": "wiki2", "target": "svc2:80", "address_id": kept["id"],
	}, cookie)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("rebind create status %d body %v", resp.StatusCode, body)
	}
	addrs = listOf(body, "addresses")
	if len(addrs) != 1 {
		t.Fatalf("expected no new address, got %d", len(addrs))
	}
	if got := listOf(body, "services")[0].(map[string]any)["address"]; got != onion {
		t.Fatalf("reused address mismatch: %v != %v", got, onion)
	}
	if got := h.published(t); got != 1 {
		t.Fatalf("expected republish, got %d", got)
	}
}

func TestAddressLifecycle(t *testing.T) {
	h := newHarness(t)
	cookie := h.login(t)
	_, body := h.do(t, http.MethodPost, "/api/services", map[string]any{"name": "wiki", "target": "svc:80"}, cookie)
	addr := listOf(body, "addresses")[0].(map[string]any)
	addrID := addr["id"].(string)

	// Rename is metadata only.
	if resp, body := h.do(t, http.MethodPatch, "/api/addresses/"+addrID, map[string]any{"label": "主站"}, cookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("rename status %d %v", resp.StatusCode, body)
	}
	// Deleting a bound address must be refused.
	if resp, _ := h.do(t, http.MethodDelete, "/api/addresses/"+addrID, nil, cookie); resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 for bound address delete, got %d", resp.StatusCode)
	}
	// Unbind, then delete works.
	if resp, _ := h.do(t, http.MethodPost, "/api/addresses/"+addrID+"/unbind", nil, cookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("unbind status %d", resp.StatusCode)
	}
	if resp, _ := h.do(t, http.MethodDelete, "/api/addresses/"+addrID, nil, cookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("delete status %d", resp.StatusCode)
	}
	if len(h.app.store.ListAddresses()) != 0 {
		t.Fatal("address still present")
	}
}

func TestVanitySearchAndAdopt(t *testing.T) {
	h := newHarness(t)
	cookie := h.login(t)

	resp, body := h.do(t, http.MethodPost, "/api/vanity", map[string]any{"prefix": "a", "want": 1}, cookie)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("start status %d body %v", resp.StatusCode, body)
	}

	var job map[string]any
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		_, list := h.do(t, http.MethodGet, "/api/vanity", nil, cookie)
		jobs := listOf(list, "jobs")
		if len(jobs) == 0 {
			t.Fatal("job disappeared")
		}
		job = jobs[0].(map[string]any)
		if job["state"] == "done" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if job["state"] != "done" {
		t.Fatalf("job never finished: %v", job["state"])
	}
	found := job["found"].([]any)
	if len(found) == 0 {
		t.Fatal("no result")
	}
	onion := found[0].(map[string]any)["onion_id"].(string)
	if !strings.HasPrefix(onion, "a") {
		t.Fatalf("result %q does not match prefix", onion)
	}
	if strings.Contains(fmt.Sprint(job), "ED25519") {
		t.Fatal("private key leaked in vanity list")
	}

	resp, body = h.do(t, http.MethodPost, "/api/vanity/"+job["id"].(string)+"/adopt", map[string]any{"index": 0}, cookie)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("adopt status %d body %v", resp.StatusCode, body)
	}
	addrs := listOf(body, "addresses")
	if len(addrs) != 1 {
		t.Fatalf("expected 1 adopted address, got %d", len(addrs))
	}
	ad := addrs[0].(map[string]any)
	if ad["address"] != onion+".onion" {
		t.Fatalf("adopted %v, want %v", ad["address"], onion+".onion")
	}
	if ad["source"] != "vanity" {
		t.Fatalf("source = %v", ad["source"])
	}
	// Adopting twice must be refused.
	if resp, _ := h.do(t, http.MethodPost, "/api/vanity/"+job["id"].(string)+"/adopt", map[string]any{"index": 0}, cookie); resp.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409 on duplicate adopt, got %d", resp.StatusCode)
	}
}

func TestVanityValidationAndStop(t *testing.T) {
	h := newHarness(t)
	cookie := h.login(t)

	for _, bad := range []string{"", "ab!", "abcdefgh", "a0"} {
		if resp, _ := h.do(t, http.MethodPost, "/api/vanity", map[string]any{"prefix": bad}, cookie); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("prefix %q should be rejected, got %d", bad, resp.StatusCode)
		}
	}

	// A 6-char prefix will not finish quickly: start it, then stop it.
	resp, body := h.do(t, http.MethodPost, "/api/vanity", map[string]any{"prefix": "abcdef", "want": 3}, cookie)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("start status %d body %v", resp.StatusCode, body)
	}
	job := listOf(body, "jobs")[0].(map[string]any)
	if job["state"] != "running" {
		t.Fatalf("state = %v", job["state"])
	}
	// Only one job at a time.
	if resp, _ := h.do(t, http.MethodPost, "/api/vanity", map[string]any{"prefix": "b"}, cookie); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("second concurrent job should be rejected, got %d", resp.StatusCode)
	}
	if resp, _ := h.do(t, http.MethodPost, "/api/vanity/"+job["id"].(string)+"/stop", nil, cookie); resp.StatusCode != http.StatusOK {
		t.Fatalf("stop status %d", resp.StatusCode)
	}
	_, list := h.do(t, http.MethodGet, "/api/vanity", nil, cookie)
	stopped := listOf(list, "jobs")[0].(map[string]any)
	if stopped["state"] != "stopped" {
		t.Fatalf("state after stop = %v", stopped["state"])
	}
}

func TestStatusAndProbe(t *testing.T) {
	h := newHarness(t)
	cookie := h.login(t)

	_, body := h.do(t, http.MethodGet, "/api/status", nil, cookie)
	if body["tor_bootstrap"] != float64(100) || body["tor_phase"] != "done" {
		t.Fatalf("bad tor status %v", body)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, body = h.do(t, http.MethodPost, "/api/probe", map[string]string{"target": ln.Addr().String()}, cookie)
	if body["ok"] != true {
		t.Fatalf("open port should probe ok: %v", body)
	}
	dead := ln.Addr().String()
	ln.Close()
	_, body = h.do(t, http.MethodPost, "/api/probe", map[string]string{"target": dead}, cookie)
	if body["ok"] != false {
		t.Fatalf("closed port should probe false: %v", body)
	}
	if resp, _ := h.do(t, http.MethodPost, "/api/probe", map[string]string{"target": "nope"}, cookie); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad target should be 400, got %d", resp.StatusCode)
	}
}

func TestValidation(t *testing.T) {
	h := newHarness(t)
	cookie := h.login(t)
	cases := []map[string]any{
		{"name": "", "target": "svc:80"},
		{"name": "x", "target": "no-port"},
		{"name": "x", "target": "svc:99999"},
		{"name": "x", "target": "svc:80", "basic_user": "bob"},
		{"name": "x", "target": "svc:80", "rate_limit": -1},
	}
	for _, c := range cases {
		if resp, _ := h.do(t, http.MethodPost, "/api/services", c, cookie); resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 for %v, got %d", c, resp.StatusCode)
		}
	}
}

func TestTorOutageKeepsStateAndRecovers(t *testing.T) {
	h := newHarness(t)
	cookie := h.login(t)
	h.do(t, http.MethodPost, "/api/services", map[string]any{"name": "a", "target": "svc:80"}, cookie)

	h.tor.mu.Lock()
	h.tor.fail = true
	h.tor.mu.Unlock()
	if err := h.app.reconcile(context.Background()); err == nil {
		t.Fatal("expected reconcile error while tor is failing")
	}
	if len(h.app.store.ListServices()) != 1 {
		t.Fatal("service dropped during tor outage")
	}

	h.tor.mu.Lock()
	h.tor.fail = false
	h.tor.mu.Unlock()
	if err := h.app.reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile after recovery: %v", err)
	}
	if got := h.published(t); got != 1 {
		t.Fatalf("expected re-publish, got %d", got)
	}
}

// Two published onions make tor answer GETINFO with a "+" data block instead of a
// single dash line; both shapes must be parsed (production hit exactly this).
func TestDetachedListBothReplyShapes(t *testing.T) {
	h := newHarness(t)
	cookie := h.login(t)
	h.do(t, http.MethodPost, "/api/services", map[string]any{"name": "a", "target": "svc:80"}, cookie)
	h.do(t, http.MethodPost, "/api/services", map[string]any{"name": "b", "target": "svc:81"}, cookie)

	ids, err := h.app.tor.DetachedOnions(context.Background())
	if err != nil {
		t.Fatalf("detached: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("parsed %d onions, want 2 (%v)", len(ids), ids)
	}
	_, body := h.do(t, http.MethodGet, "/api/status", nil, cookie)
	if body["tor_services"] != float64(2) {
		t.Fatalf("tor_services = %v, want 2", body["tor_services"])
	}
}

// tor restarting wipes its in-memory services while the panel still believes they
// are published; the reconcile loop must notice and re-create them.
func TestTorRestartRepublishes(t *testing.T) {
	h := newHarness(t)
	cookie := h.login(t)
	h.do(t, http.MethodPost, "/api/services", map[string]any{"name": "a", "target": "svc:80"}, cookie)
	if got := h.published(t); got != 1 {
		t.Fatalf("initial publish = %d, want 1", got)
	}

	h.tor.mu.Lock()
	h.tor.added = map[string]string{}
	h.tor.mu.Unlock()

	if err := h.app.reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := h.published(t); got != 1 {
		t.Fatalf("after tor restart published = %d, want 1", got)
	}
}
