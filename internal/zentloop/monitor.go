package zentloop

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/zentproxy/zentproxy/internal/db"
)

type Health struct {
	Status       string     `json:"status"`
	Reachable    bool       `json:"reachable"`
	Verified     bool       `json:"verified"`
	Verification string     `json:"verification"`
	LatencyMS    int64      `json:"latency_ms"`
	LastChecked  *time.Time `json:"last_checked,omitempty"`
	LastSuccess  *time.Time `json:"last_success,omitempty"`
	Error        string     `json:"error,omitempty"`
}

type Monitor struct {
	store  *db.Store
	mu     sync.RWMutex
	health Health
	client *http.Client
}

func NewMonitor(store *db.Store) *Monitor {
	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: 15 * time.Second}).DialContext,
		TLSHandshakeTimeout:   2 * time.Second,
		ResponseHeaderTimeout: 3 * time.Second,
		IdleConnTimeout:       30 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	return &Monitor{store: store, health: Health{Status: "disabled", Verification: "disabled"}, client: &http.Client{Transport: transport, Timeout: 4 * time.Second}}
}

func (m *Monitor) Start(ctx context.Context) {
	m.CheckNow(ctx)
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.CheckNow(ctx)
			}
		}
	}()
}

func (m *Monitor) Snapshot() Health {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.health
}

func (m *Monitor) Healthy() bool {
	h := m.Snapshot()
	return h.Status == "online"
}

func (m *Monitor) CheckNow(ctx context.Context) Health {
	cfg, err := m.store.GetZentLoop()
	now := time.Now().UTC()
	if err != nil {
		return m.set(Health{Status: "offline", Verification: "unknown", LastChecked: &now, Error: "cannot load ZentLoop configuration"})
	}
	if !cfg.Enabled {
		return m.set(Health{Status: "disabled", Verification: "disabled", LastChecked: &now})
	}
	u, err := url.Parse(strings.TrimSpace(cfg.Upstream))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return m.set(Health{Status: "offline", Verification: "invalid_config", LastChecked: &now, Error: "invalid ZentLoop upstream URL"})
	}
	checkURL := *u
	checkURL.Path = "/.well-known/zentloop/integration-check"
	checkURL.RawQuery = ""
	checkURL.Fragment = ""
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, checkURL.String(), nil)
	target := "zentproxy-health.invalid"
	req.Header.Set("X-ZentLoop-Integration", "zentproxy")
	req.Header.Set("X-ZentLoop-Target", target)
	req.Header.Set("X-ZentLoop-Catch-All", "0")
	ts := fmt.Sprintf("%d", now.Unix())
	if cfg.Secret != "" {
		req.Header.Set("X-ZentLoop-Timestamp", ts)
		req.Header.Set("X-ZentLoop-Signature", "sha256="+Signature(cfg.Secret, ts, "zentproxy", target, false, http.MethodGet, checkURL.RequestURI()))
	}
	started := time.Now()
	resp, err := m.client.Do(req)
	latency := time.Since(started).Milliseconds()
	if err != nil {
		return m.set(Health{Status: "offline", Verification: "unreachable", LastChecked: &now, LatencyMS: latency, Error: err.Error()})
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	h := Health{Status: "online", Reachable: true, LatencyMS: latency, LastChecked: &now, LastSuccess: &now}
	if cfg.Secret == "" {
		h.Verification = "not_configured"
		return m.set(h)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		h.Status = "offline"
		h.Verification = "secret_mismatch"
		h.Error = "ZentLoop rejected the signed integration check"
		return m.set(h)
	}
	if resp.Header.Get("X-ZentLoop-Integration-Verified") == "1" {
		h.Verified = true
		h.Verification = "verified"
		return m.set(h)
	}
	h.Status = "degraded"
	h.Verification = "unverified"
	h.Error = "ZentLoop is reachable, but did not confirm the signed integration check"
	return m.set(h)
}

func (m *Monitor) set(h Health) Health {
	m.mu.Lock()
	m.health = h
	m.mu.Unlock()
	return h
}
