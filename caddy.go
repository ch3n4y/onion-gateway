package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Route is one onion host -> upstream rule for Caddy.
type Route struct {
	OnionID   string
	Target    string
	BasicUser string
	BasicHash string
	RateLimit int
}

// CaddyClient owns the whole Caddy runtime config. The panel rebuilds the full
// config from its own state and POSTs it to the admin API, which keeps Caddy and
// the panel from ever drifting apart (no hand-written Caddyfile per site).
type CaddyClient struct {
	adminURL    string
	adminListen string
	serveAddr   string
	hc          *http.Client
}

func NewCaddyClient(adminURL, adminListen, serveAddr string) *CaddyClient {
	return &CaddyClient{
		adminURL:    strings.TrimRight(adminURL, "/"),
		adminListen: adminListen,
		serveAddr:   serveAddr,
		hc:          &http.Client{Timeout: 15 * time.Second},
	}
}

type j = map[string]any

func (c *CaddyClient) routes(list []Route) []any {
	routes := make([]any, 0, len(list)+1)
	for _, r := range list {
		if r.OnionID == "" {
			continue
		}
		handlers := make([]any, 0, 3)
		if r.RateLimit > 0 {
			// Key on the onion host: every client reaches Caddy from the tor
			// container IP, so client-IP keying would put the whole world in one
			// bucket.
			handlers = append(handlers, j{
				"handler": "rate_limit",
				"rate_limits": j{
					"onion": j{
						"key":        "{http.request.host}",
						"window":     "1m",
						"max_events": r.RateLimit,
					},
				},
			})
		}
		if r.BasicUser != "" && r.BasicHash != "" {
			handlers = append(handlers, j{
				"handler": "authentication",
				"providers": j{
					"http_basic": j{
						"hash": j{"algorithm": "bcrypt"},
						"accounts": []any{
							j{"username": r.BasicUser, "password": r.BasicHash},
						},
						"realm": "onion-gateway",
					},
				},
			})
		}
		handlers = append(handlers, j{
			"handler":   "reverse_proxy",
			"upstreams": []any{j{"dial": r.Target}},
			"headers": j{
				"request": j{
					"set": j{
						"X-Forwarded-Host": []string{"{http.request.host}"},
						"X-Real-IP":        []string{"{http.request.remote.host}"},
					},
				},
			},
		})
		routes = append(routes, j{
			"match":    []any{j{"host": []string{r.OnionID + ".onion"}}},
			"handle":   handlers,
			"terminal": true,
		})
	}
	routes = append(routes, j{
		"handle": []any{j{
			"handler":     "static_response",
			"status_code": 404,
			"body":        "onion-gateway: no such service",
		}},
	})
	return routes
}

func (c *CaddyClient) config(list []Route) j {
	return j{
		"admin": j{"listen": c.adminListen},
		"apps": j{
			"http": j{
				"servers": j{
					"srv0": j{
						"listen": []string{c.serveAddr},
						// Onion services are plain HTTP and ACME cannot validate a
						// .onion name: without this Caddy turns the server into an
						// HTTPS server and tries to obtain certificates for it
						// (leaking the onion hostnames to the CA too).
						"automatic_https": j{"disable": true},
						"routes":          c.routes(list),
						// Empty object = access logs to stdout in JSON.
						"logs": j{},
					},
				},
			},
		},
	}
}

// Apply pushes the complete desired config. Safe to call repeatedly.
func (c *CaddyClient) Apply(ctx context.Context, list []Route) error {
	body, err := json.Marshal(c.config(list))
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.adminURL+"/load", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "must-revalidate")
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("caddy admin unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var msg bytes.Buffer
		_, _ = msg.ReadFrom(resp.Body)
		return fmt.Errorf("caddy /load failed: %s: %s", resp.Status, strings.TrimSpace(msg.String()))
	}
	return nil
}

func (c *CaddyClient) Status(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.adminURL+"/config/", nil)
	if err != nil {
		return err
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("caddy admin unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("caddy admin returned %s", resp.Status)
	}
	return nil
}
