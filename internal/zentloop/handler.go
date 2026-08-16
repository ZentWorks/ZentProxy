package zentloop

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/ZentWorks/ZentProxy/internal/db"
)

type Handler struct {
	store   *db.Store
	monitor *Monitor
}

func New(store *db.Store, monitors ...*Monitor) *Handler {
	var monitor *Monitor
	if len(monitors) > 0 {
		monitor = monitors[0]
	}
	return &Handler{store: store, monitor: monitor}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.store.GetZentLoop()
	if err != nil || !cfg.Enabled {
		http.NotFound(w, r)
		return
	}
	if h.monitor != nil && !h.monitor.Healthy() {
		if cfg.Fallback == "503" {
			http.Error(w, "ZentLoop integration unavailable", http.StatusServiceUnavailable)
		} else {
			http.Error(w, "ZentLoop integration unavailable", http.StatusForbidden)
		}
		return
	}
	u, err := url.Parse(cfg.Upstream)
	if err != nil || u.Scheme == "" || u.Host == "" {
		http.Error(w, "integration upstream is invalid", http.StatusBadGateway)
		return
	}
	catchAll := r.Header.Get("X-ZentLoop-Catch-All") != "0"
	target := canonicalTarget(r.Host)
	if target == "" {
		target = canonicalTarget(r.Header.Get("X-Forwarded-Host"))
	}
	ts := fmt.Sprintf("%d", time.Now().UTC().Unix())
	clientIP := canonicalClientIP(r)
	proxy := &httputil.ReverseProxy{}
	proxy.Transport = &http.Transport{DialContext: (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: 15 * time.Second}).DialContext, TLSHandshakeTimeout: 2 * time.Second, ResponseHeaderTimeout: 3 * time.Second, IdleConnTimeout: 30 * time.Second, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	proxy.Rewrite = func(pr *httputil.ProxyRequest) {
		pr.SetURL(u)
		pr.Out.Host = u.Host
		if clientIP != "" {
			pr.Out.Header.Set("X-Real-IP", clientIP)
			pr.Out.Header.Set("X-Forwarded-For", clientIP)
		}
		if proto := strings.TrimSpace(pr.In.Header.Get("X-Forwarded-Proto")); proto != "" {
			pr.Out.Header.Set("X-Forwarded-Proto", proto)
		}
		if host := strings.TrimSpace(pr.In.Header.Get("X-Forwarded-Host")); host != "" {
			pr.Out.Header.Set("X-Forwarded-Host", host)
		}
		pr.Out.Header.Set("X-ZentLoop-Integration", "zentproxy")
		pr.Out.Header.Set("X-ZentLoop-Target", target)
		if catchAll {
			pr.Out.Header.Set("X-ZentLoop-Catch-All", "1")
		} else {
			pr.Out.Header.Set("X-ZentLoop-Catch-All", "0")
		}
		if cfg.Secret != "" {
			pr.Out.Header.Set("X-ZentLoop-Timestamp", ts)
			pr.Out.Header.Set("X-ZentLoop-Signature", "sha256="+Signature(cfg.Secret, ts, "zentproxy", target, catchAll, r.Method, r.URL.RequestURI()))
		}
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, e error) {
		http.Error(w, "integration upstream unavailable", http.StatusBadGateway)
	}
	proxy.ServeHTTP(w, r)
}

func canonicalClientIP(r *http.Request) string {
	for _, value := range []string{r.Header.Get("X-Real-IP"), firstForwardedIP(r.Header.Get("X-Forwarded-For"))} {
		value = strings.TrimSpace(value)
		if ip := net.ParseIP(strings.Trim(value, "[]")); ip != nil {
			return ip.String()
		}
	}
	if host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
			return ip.String()
		}
	}
	return ""
}

func firstForwardedIP(value string) string {
	if i := strings.IndexByte(value, ','); i >= 0 {
		value = value[:i]
	}
	return strings.TrimSpace(value)
}

func Signature(secret, timestamp, name, target string, catchAll bool, method, requestURI string) string {
	ca := "0"
	if catchAll {
		ca = "1"
	}
	payload := strings.Join([]string{"v1", timestamp, name, target, ca, strings.ToUpper(method), requestURI}, "\n")
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func canonicalTarget(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if i := strings.IndexByte(v, ':'); i >= 0 {
		v = v[:i]
	}
	if v == "" || len(v) > 255 || strings.ContainsAny(v, "/\\?#@ \t\r\n") {
		return ""
	}
	return v
}
