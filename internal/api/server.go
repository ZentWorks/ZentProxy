package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ZentWorks/ZentProxy/internal/certificates"
	"github.com/ZentWorks/ZentProxy/internal/config"
	"github.com/ZentWorks/ZentProxy/internal/db"
	"github.com/ZentWorks/ZentProxy/internal/migration"
	"github.com/ZentWorks/ZentProxy/internal/model"
	"github.com/ZentWorks/ZentProxy/internal/providers"
	"github.com/ZentWorks/ZentProxy/internal/proxy"
	"github.com/ZentWorks/ZentProxy/internal/webui"
	"github.com/ZentWorks/ZentProxy/internal/zentloop"
)

type Server struct {
	cfg         config.Config
	store       *db.Store
	proxy       *proxy.Manager
	providers   *providers.Manager
	certs       *certificates.Manager
	mux         *http.ServeMux
	migrationMu sync.Mutex
	zentLoop    *zentloop.Monitor
	updates     *releaseChecker
}

type principal struct {
	kind   string
	name   string
	userID int64
	csrf   string
	scopes map[string]bool
}

type ctxKey string

const principalKey ctxKey = "principal"

var allowedScopes = []string{
	"system:read", "hosts:read", "hosts:write", "routing:read", "routing:write", "access:read", "access:write", "certificates:read", "certificates:write", "stats:read", "providers:read", "providers:write", "integrations:read", "integrations:write", "audit:read",
}

func New(cfg config.Config, store *db.Store, pm *proxy.Manager, providerManager *providers.Manager, certManager *certificates.Manager, monitors ...*zentloop.Monitor) *Server {
	var zentLoopMonitor *zentloop.Monitor
	if len(monitors) > 0 {
		zentLoopMonitor = monitors[0]
	}
	s := &Server{cfg: cfg, store: store, proxy: pm, providers: providerManager, certs: certManager, zentLoop: zentLoopMonitor, updates: newReleaseChecker(cfg.Version), mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler {
	return securityHeaders(s.mux)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.health)
	s.mux.HandleFunc("POST /api/v1/auth/login", s.login)
	s.mux.Handle("GET /api/v1/openapi.yaml", http.HandlerFunc(s.openapi))
	s.mux.Handle("GET /api/docs", http.HandlerFunc(s.apiDocs))
	s.mux.Handle("GET /api/docs/", http.HandlerFunc(s.apiDocs))

	s.mux.Handle("GET /api/v1/auth/me", s.require("system:read", http.HandlerFunc(s.me)))
	s.mux.Handle("POST /api/v1/auth/logout", s.require("system:read", http.HandlerFunc(s.logout)))
	s.mux.Handle("PUT /api/v1/user/preferences/language", s.requireSession(http.HandlerFunc(s.setLanguage)))
	s.mux.Handle("PUT /api/v1/user/preferences/proxy-hosts-view", s.requireSession(http.HandlerFunc(s.setProxyHostsView)))
	s.mux.Handle("GET /api/v1/system/info", s.require("system:read", http.HandlerFunc(s.systemInfo)))
	s.mux.Handle("GET /api/v1/system/update", s.requireSession(http.HandlerFunc(s.systemUpdate)))
	s.mux.Handle("GET /api/v1/system/capabilities", s.require("system:read", http.HandlerFunc(s.capabilities)))

	s.mux.Handle("GET /api/v1/hosts", s.require("hosts:read", http.HandlerFunc(s.hostsList)))
	s.mux.Handle("POST /api/v1/hosts", s.require("hosts:write", http.HandlerFunc(s.hostsCreate)))
	s.mux.Handle("GET /api/v1/hosts/{id}", s.require("hosts:read", http.HandlerFunc(s.hostGet)))
	s.mux.Handle("PUT /api/v1/hosts/{id}", s.require("hosts:write", http.HandlerFunc(s.hostUpdate)))
	s.mux.Handle("DELETE /api/v1/hosts/{id}", s.require("hosts:write", http.HandlerFunc(s.hostDelete)))

	s.mux.Handle("GET /api/v1/access-lists", s.require("access:read", http.HandlerFunc(s.accessListsList)))
	s.mux.Handle("POST /api/v1/access-lists", s.require("access:write", http.HandlerFunc(s.accessListCreate)))
	s.mux.Handle("GET /api/v1/access-lists/{id}", s.require("access:read", http.HandlerFunc(s.accessListGet)))
	s.mux.Handle("PUT /api/v1/access-lists/{id}", s.require("access:write", http.HandlerFunc(s.accessListUpdate)))
	s.mux.Handle("DELETE /api/v1/access-lists/{id}", s.require("access:write", http.HandlerFunc(s.accessListDelete)))
	s.mux.Handle("GET /api/v1/access-lists/{id}/users", s.require("access:read", http.HandlerFunc(s.accessListUsersList)))
	s.mux.Handle("PUT /api/v1/access-lists/{id}/users/{username}", s.require("access:write", http.HandlerFunc(s.accessListUserUpsert)))
	s.mux.Handle("DELETE /api/v1/access-lists/{id}/users/{username}", s.require("access:write", http.HandlerFunc(s.accessListUserDelete)))
	s.mux.Handle("GET /api/v1/redirect-hosts", s.require("routing:read", http.HandlerFunc(s.redirectHostsList)))
	s.mux.Handle("POST /api/v1/redirect-hosts", s.require("routing:write", http.HandlerFunc(s.redirectHostCreate)))
	s.mux.Handle("PUT /api/v1/redirect-hosts/{id}", s.require("routing:write", http.HandlerFunc(s.redirectHostUpdate)))
	s.mux.Handle("DELETE /api/v1/redirect-hosts/{id}", s.require("routing:write", http.HandlerFunc(s.redirectHostDelete)))
	s.mux.Handle("GET /api/v1/dead-hosts", s.require("routing:read", http.HandlerFunc(s.deadHostsList)))
	s.mux.Handle("POST /api/v1/dead-hosts", s.require("routing:write", http.HandlerFunc(s.deadHostCreate)))
	s.mux.Handle("PUT /api/v1/dead-hosts/{id}", s.require("routing:write", http.HandlerFunc(s.deadHostUpdate)))
	s.mux.Handle("DELETE /api/v1/dead-hosts/{id}", s.require("routing:write", http.HandlerFunc(s.deadHostDelete)))
	s.mux.Handle("GET /api/v1/streams", s.require("routing:read", http.HandlerFunc(s.streamsList)))
	s.mux.Handle("POST /api/v1/streams", s.require("routing:write", http.HandlerFunc(s.streamCreate)))
	s.mux.Handle("PUT /api/v1/streams/{id}", s.require("routing:write", http.HandlerFunc(s.streamUpdate)))
	s.mux.Handle("DELETE /api/v1/streams/{id}", s.require("routing:write", http.HandlerFunc(s.streamDelete)))

	s.mux.Handle("GET /api/v1/certificates", s.require("certificates:read", http.HandlerFunc(s.certificatesList)))
	s.mux.Handle("PUT /api/v1/certificates/{id}", s.require("certificates:write", http.HandlerFunc(s.certificateUpdateMetadata)))
	s.mux.Handle("POST /api/v1/certificates/letsencrypt", s.require("certificates:write", http.HandlerFunc(s.certificateIssue)))
	s.mux.Handle("POST /api/v1/certificates/import", s.require("certificates:write", http.HandlerFunc(s.certificateImport)))
	s.mux.Handle("POST /api/v1/certificates/{id}/renew", s.require("certificates:write", http.HandlerFunc(s.certificateRenew)))
	s.mux.Handle("DELETE /api/v1/certificates/{id}", s.require("certificates:write", http.HandlerFunc(s.certificateDelete)))

	s.mux.Handle("GET /api/v1/stats/summary", s.require("stats:read", http.HandlerFunc(s.statsSummary)))
	s.mux.Handle("GET /api/v1/stats/requests", s.require("stats:read", http.HandlerFunc(s.statsRequests)))

	s.mux.Handle("GET /api/v1/trusted-proxy-providers", s.require("providers:read", http.HandlerFunc(s.providersList)))
	s.mux.Handle("POST /api/v1/trusted-proxy-providers", s.require("providers:write", http.HandlerFunc(s.providerCreate)))
	s.mux.Handle("PUT /api/v1/trusted-proxy-providers/{id}", s.require("providers:write", http.HandlerFunc(s.providerUpdate)))
	s.mux.Handle("DELETE /api/v1/trusted-proxy-providers/{id}", s.require("providers:write", http.HandlerFunc(s.providerDelete)))
	s.mux.Handle("POST /api/v1/trusted-proxy-providers/{id}/refresh", s.require("providers:write", http.HandlerFunc(s.providerRefresh)))

	s.mux.Handle("GET /api/v1/integrations/zentloop", s.require("integrations:read", http.HandlerFunc(s.zentLoopGet)))
	s.mux.Handle("PUT /api/v1/integrations/zentloop", s.require("integrations:write", http.HandlerFunc(s.zentLoopSet)))
	s.mux.Handle("POST /api/v1/integrations/zentloop/check", s.require("integrations:read", http.HandlerFunc(s.zentLoopCheck)))

	// API key lifecycle is intentionally session-admin only. API keys cannot mint more API keys.
	s.mux.Handle("GET /api/v1/api-keys", s.requireSession(http.HandlerFunc(s.apiKeysList)))
	s.mux.Handle("POST /api/v1/api-keys", s.requireSession(http.HandlerFunc(s.apiKeysCreate)))
	s.mux.Handle("DELETE /api/v1/api-keys/{id}", s.requireSession(http.HandlerFunc(s.apiKeyRevoke)))
	s.mux.Handle("GET /api/v1/audit", s.require("audit:read", http.HandlerFunc(s.audit)))

	// Migration credentials can reach private-network services. Keep these endpoints
	// interactive-admin only instead of exposing them to API keys.
	s.mux.Handle("POST /api/v1/migration/analyze", s.requireSession(http.HandlerFunc(s.migrationAnalyze)))
	s.mux.Handle("POST /api/v1/migration/import", s.requireSession(http.HandlerFunc(s.migrationImport)))

	s.mux.Handle("/", webui.Handler())
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		if r.URL.Path == "/api/docs" || strings.HasPrefix(r.URL.Path, "/api/docs/") {
			w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self' data:; base-uri 'self'; frame-ancestors 'none'")
		} else {
			w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authenticate(r *http.Request) (principal, bool, error) {
	if h := strings.TrimSpace(r.Header.Get("Authorization")); strings.HasPrefix(strings.ToLower(h), "bearer ") {
		token := strings.TrimSpace(h[7:])
		_, name, scopes, ok, err := s.store.ValidateAPIKey(token)
		if err != nil || !ok {
			return principal{}, false, err
		}
		m := map[string]bool{}
		for _, scope := range scopes {
			m[scope] = true
		}
		return principal{kind: "api-key", name: name, scopes: m}, true, nil
	}
	c, err := r.Cookie("zp_session")
	if err != nil {
		return principal{}, false, nil
	}
	uid, csrf, ok, err := s.store.ValidateSession(c.Value)
	if err != nil || !ok {
		return principal{}, false, err
	}
	return principal{kind: "session", name: s.store.Username(uid), userID: uid, csrf: csrf, scopes: map[string]bool{"*": true}}, true, nil
}

func (s *Server) require(scope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok, err := s.authenticate(r)
		if err != nil {
			jsonError(w, 500, "authentication failed")
			return
		}
		if !ok {
			jsonError(w, 401, "authentication required")
			return
		}
		if !p.scopes["*"] && !p.scopes[scope] {
			jsonError(w, 403, "missing scope: "+scope)
			return
		}
		if p.kind == "session" && isMutation(r.Method) && r.Header.Get("X-ZentProxy-CSRF") != p.csrf {
			jsonError(w, 403, "invalid CSRF token")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey, p)))
	})
}

func (s *Server) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok, err := s.authenticate(r)
		if err != nil {
			jsonError(w, 500, "authentication failed")
			return
		}
		if !ok {
			jsonError(w, 401, "authentication required")
			return
		}
		if p.kind != "session" {
			jsonError(w, 403, "interactive administrator session required")
			return
		}
		if isMutation(r.Method) && r.Header.Get("X-ZentProxy-CSRF") != p.csrf {
			jsonError(w, 403, "invalid CSRF token")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey, p)))
	})
}

func isMutation(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}
func actor(r *http.Request) string {
	if p, ok := r.Context().Value(principalKey).(principal); ok {
		return p.kind + ":" + p.name
	}
	return "unknown"
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		jsonError(w, 503, "database unavailable")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "service": "zentproxy", "version": s.cfg.Version})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &in); err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	uid, ok, err := s.store.Authenticate(strings.TrimSpace(in.Username), in.Password)
	if err != nil {
		jsonError(w, 500, "login failed")
		return
	}
	if !ok {
		time.Sleep(250 * time.Millisecond)
		jsonError(w, 401, "invalid credentials")
		return
	}
	token, csrf, expires, err := s.store.CreateSession(uid, 24*time.Hour)
	if err != nil {
		jsonError(w, 500, "session creation failed")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "zp_session", Value: token, Path: "/", HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: 86400})
	_ = os.Remove(filepath.Join(s.cfg.DataDir, "bootstrap-admin.txt"))
	s.store.AddAudit("session:"+strings.TrimSpace(in.Username), "login", "session", "", "")
	writeJSON(w, 200, map[string]any{"username": strings.TrimSpace(in.Username), "csrf_token": csrf, "expires_at": expires, "language": s.store.UserLanguage(uid), "proxy_hosts_view": s.store.UserProxyHostsView(uid)})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(principal)
	language := "en"
	if p.kind == "session" {
		language = s.store.UserLanguage(p.userID)
	}
	writeJSON(w, 200, map[string]any{"kind": p.kind, "name": p.name, "csrf_token": p.csrf, "language": language, "proxy_hosts_view": s.store.UserProxyHostsView(p.userID), "default_acme_email": s.cfg.AdminEmail})
}

func (s *Server) setLanguage(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(principal)
	var in struct {
		Language string `json:"language"`
	}
	if err := decodeJSON(r, &in); err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	language := strings.ToLower(strings.TrimSpace(in.Language))
	if language != "de" && language != "en" && language != "fr" && language != "nl" && language != "es" {
		jsonError(w, 422, "unsupported language")
		return
	}
	if err := s.store.SetUserLanguage(p.userID, language); err != nil {
		jsonError(w, 500, "cannot save language")
		return
	}
	s.store.AddAudit(actor(r), "update", "user-preferences", strconv.FormatInt(p.userID, 10), "language="+language)
	writeJSON(w, 200, map[string]any{"language": language})
}
func (s *Server) setProxyHostsView(w http.ResponseWriter, r *http.Request) {
	p := r.Context().Value(principalKey).(principal)
	var in struct {
		View string `json:"view"`
	}
	if err := decodeJSON(r, &in); err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	view := strings.ToLower(strings.TrimSpace(in.View))
	if view != "list" && view != "grouped" {
		jsonError(w, 422, "unsupported proxy hosts view")
		return
	}
	if err := s.store.SetUserProxyHostsView(p.userID, view); err != nil {
		jsonError(w, 500, "cannot save proxy hosts view")
		return
	}
	s.store.AddAudit(actor(r), "update", "user-preferences", strconv.FormatInt(p.userID, 10), "proxy_hosts_view="+view)
	writeJSON(w, 200, map[string]any{"view": view})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, e := r.Cookie("zp_session"); e == nil {
		_ = s.store.DeleteSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "zp_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) systemInfo(w http.ResponseWriter, r *http.Request) {
	hosts, _ := s.store.ListHosts()
	enabled := 0
	for _, h := range hosts {
		if h.Enabled {
			enabled++
		}
	}
	writeJSON(w, 200, map[string]any{"name": "ZentProxy", "version": s.cfg.Version, "commit": s.cfg.Commit, "hosts": len(hosts), "enabled_hosts": enabled, "raw_retention_days": s.cfg.RawRetentionDays})
}
func (s *Server) capabilities(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"api_version": "v1", "features": []string{"proxy-hosts", "redirect-hosts", "dead-hosts", "streams", "access-lists", "letsencrypt", "certificate-auto-renew", "per-host-analytics", "trusted-proxy-providers", "zentloop-v1", "zentloop-rules", "api-keys", "audit-log", "openapi", "full-migration", "i18n", "documentation"}, "api_key_scopes": allowedScopes})
}

func (s *Server) hostsList(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.ListHosts()
	if err != nil {
		jsonError(w, 500, "cannot list hosts")
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) hostGet(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	h, err := s.store.GetHost(id)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, 404, "host not found")
		return
	}
	if err != nil {
		jsonError(w, 500, "cannot load host")
		return
	}
	writeJSON(w, 200, h)
}
func (s *Server) hostsCreate(w http.ResponseWriter, r *http.Request) {
	var in model.HostInput
	if err := decodeJSON(r, &in); err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	in, err := proxy.NormalizeAndValidate(in)
	if err != nil {
		jsonError(w, 422, err.Error())
		return
	}
	if in.TrustedProxyProviderID != nil {
		if _, err := s.store.GetProvider(*in.TrustedProxyProviderID); err != nil {
			jsonError(w, 422, "trusted proxy provider does not exist")
			return
		}
	}
	if in.CertificateID != nil {
		if _, err := s.store.GetCertificate(*in.CertificateID); err != nil {
			jsonError(w, 422, "certificate does not exist")
			return
		}
	}
	if in.AccessListID != nil {
		if _, err := s.store.GetAccessList(*in.AccessListID); err != nil {
			jsonError(w, 422, "access list does not exist")
			return
		}
	}
	existing, err := s.store.ListHosts()
	if err != nil {
		jsonError(w, 500, "cannot validate domains")
		return
	}
	if err := proxy.CheckDomainConflicts(existing, in.Domains, 0); err != nil {
		jsonError(w, 409, err.Error())
		return
	}
	h, err := s.store.CreateHost(in)
	if err != nil {
		jsonError(w, 500, "cannot create host")
		return
	}
	if err := s.proxy.Apply(); err != nil {
		jsonError(w, 500, "host saved but proxy reload failed: "+err.Error())
		return
	}
	s.store.AddAudit(actor(r), "create", "host", strconv.FormatInt(h.ID, 10), h.Name)
	writeJSON(w, 201, h)
}
func (s *Server) hostUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var in model.HostInput
	if err := decodeJSON(r, &in); err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	in, err := proxy.NormalizeAndValidate(in)
	if err != nil {
		jsonError(w, 422, err.Error())
		return
	}
	if in.TrustedProxyProviderID != nil {
		if _, err := s.store.GetProvider(*in.TrustedProxyProviderID); err != nil {
			jsonError(w, 422, "trusted proxy provider does not exist")
			return
		}
	}
	if in.CertificateID != nil {
		if _, err := s.store.GetCertificate(*in.CertificateID); err != nil {
			jsonError(w, 422, "certificate does not exist")
			return
		}
	}
	if in.AccessListID != nil {
		if _, err := s.store.GetAccessList(*in.AccessListID); err != nil {
			jsonError(w, 422, "access list does not exist")
			return
		}
	}
	existing, err := s.store.ListHosts()
	if err != nil {
		jsonError(w, 500, "cannot validate domains")
		return
	}
	if err := proxy.CheckDomainConflicts(existing, in.Domains, id); err != nil {
		jsonError(w, 409, err.Error())
		return
	}
	h, err := s.store.UpdateHost(id, in)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, 404, "host not found")
		return
	}
	if err != nil {
		jsonError(w, 500, "cannot update host")
		return
	}
	if err := s.proxy.Apply(); err != nil {
		jsonError(w, 500, "host saved but proxy reload failed: "+err.Error())
		return
	}
	s.store.AddAudit(actor(r), "update", "host", strconv.FormatInt(h.ID, 10), h.Name)
	writeJSON(w, 200, h)
}
func (s *Server) hostDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteHost(id); errors.Is(err, sql.ErrNoRows) {
		jsonError(w, 404, "host not found")
		return
	} else if err != nil {
		jsonError(w, 500, "cannot delete host")
		return
	}
	if err := s.proxy.Apply(); err != nil {
		jsonError(w, 500, "host deleted but proxy reload failed: "+err.Error())
		return
	}
	s.store.AddAudit(actor(r), "delete", "host", strconv.FormatInt(id, 10), "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) accessListsList(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.ListAccessLists()
	if err != nil {
		jsonError(w, 500, "cannot list access lists")
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) accessListCreate(w http.ResponseWriter, r *http.Request) {
	var in model.AccessListInput
	if err := decodeJSON(r, &in); err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	if msg := validateAccessListInput(&in); msg != "" {
		jsonError(w, 422, msg)
		return
	}
	a, err := s.store.CreateAccessList(in)
	if err != nil {
		jsonError(w, 500, "cannot create access list")
		return
	}
	s.store.AddAudit(actor(r), "create", "access-list", strconv.FormatInt(a.ID, 10), a.Name)
	writeJSON(w, 201, a)
}
func validateAccessListInput(in *model.AccessListInput) string {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return "name is required"
	}
	if strings.TrimSpace(in.AuthFile) != "" {
		return "auth_file is managed by ZentProxy"
	}
	for i := range in.Rules {
		in.Rules[i].Directive = strings.ToLower(strings.TrimSpace(in.Rules[i].Directive))
		in.Rules[i].Address = strings.TrimSpace(in.Rules[i].Address)
		if in.Rules[i].Directive != "allow" && in.Rules[i].Directive != "deny" {
			return "access rule directive must be allow or deny"
		}
		if in.Rules[i].Address == "" {
			return "access rule address is required"
		}
	}
	return ""
}
func (s *Server) accessListGet(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	v, err := s.store.GetAccessList(id)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, 404, "access list not found")
		return
	}
	if err != nil {
		jsonError(w, 500, "cannot read access list")
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) accessListUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	old, err := s.store.GetAccessList(id)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, 404, "access list not found")
		return
	}
	if err != nil {
		jsonError(w, 500, "cannot read access list")
		return
	}
	var in model.AccessListInput
	if err := decodeJSON(r, &in); err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	if strings.TrimSpace(in.AuthFile) == "" {
		in.AuthFile = old.AuthFile
	}
	if in.AuthFile != old.AuthFile {
		jsonError(w, 422, "auth_file is managed by ZentProxy")
		return
	}
	// preserve the managed auth path while validating the editable fields.
	managed := in.AuthFile
	in.AuthFile = ""
	if msg := validateAccessListInput(&in); msg != "" {
		jsonError(w, 422, msg)
		return
	}
	in.AuthFile = managed
	v, err := s.store.UpdateAccessList(id, in)
	if err != nil {
		jsonError(w, 500, "cannot update access list")
		return
	}
	if err := s.proxy.Apply(); err != nil {
		_, _ = s.store.UpdateAccessList(id, model.AccessListInput{Name: old.Name, SatisfyAny: old.SatisfyAny, PassAuth: old.PassAuth, AuthEnabled: old.AuthEnabled, Rules: old.Rules, AuthFile: old.AuthFile})
		_ = s.proxy.Apply()
		jsonError(w, 500, "access list saved but proxy activation failed: "+err.Error())
		return
	}
	s.store.AddAudit(actor(r), "update", "access-list", strconv.FormatInt(id, 10), v.Name)
	writeJSON(w, 200, v)
}
func accessListUsernames(path string) ([]string, error) {
	if strings.TrimSpace(path) == "" {
		return []string{}, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	users := []string{}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, _, ok := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		if ok && name != "" && !seen[name] {
			seen[name] = true
			users = append(users, name)
		}
	}
	return users, nil
}

func validateAccessUsername(raw string) (string, string) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", "username is required"
	}
	if len(name) > 128 || strings.ContainsAny(name, ":\r\n\x00") {
		return "", "username contains unsupported characters"
	}
	return name, ""
}

func (s *Server) managedAccessAuthFile(id int64) string {
	return filepath.Join(s.cfg.DataDir, "access-lists", strconv.FormatInt(id, 10)+".htpasswd")
}

func (s *Server) accessListUsersList(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	v, err := s.store.GetAccessList(id)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, 404, "access list not found")
		return
	}
	if err != nil {
		jsonError(w, 500, "cannot read access list")
		return
	}
	users, err := accessListUsernames(v.AuthFile)
	if err != nil {
		jsonError(w, 500, "cannot read access-list credentials")
		return
	}
	writeJSON(w, 200, users)
}

func (s *Server) accessListUserUpsert(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	v, err := s.store.GetAccessList(id)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, 404, "access list not found")
		return
	}
	if err != nil {
		jsonError(w, 500, "cannot read access list")
		return
	}
	username, msg := validateAccessUsername(r.PathValue("username"))
	if msg != "" {
		jsonError(w, 422, msg)
		return
	}
	var in struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &in); err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	if len(in.Password) < 8 || len(in.Password) > 512 {
		jsonError(w, 422, "password must be between 8 and 512 characters")
		return
	}
	path := v.AuthFile
	if strings.TrimSpace(path) == "" {
		path = s.managedAccessAuthFile(id)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		jsonError(w, 500, "cannot prepare access-list credentials")
		return
	}
	args := []string{"-iB"}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		args = append(args, "-c")
	}
	args = append(args, path, username)
	cmd := exec.Command("htpasswd", args...)
	cmd.Stdin = strings.NewReader(in.Password + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		jsonError(w, 500, "cannot update access-list credentials: "+strings.TrimSpace(string(out)))
		return
	}
	_ = os.Chmod(path, 0o600)
	v.AuthFile = path
	v.AuthEnabled = true
	if _, err := s.store.UpdateAccessList(id, model.AccessListInput{Name: v.Name, SatisfyAny: v.SatisfyAny, PassAuth: v.PassAuth, AuthEnabled: v.AuthEnabled, Rules: v.Rules, AuthFile: v.AuthFile}); err != nil {
		jsonError(w, 500, "credentials were written but access-list metadata could not be updated")
		return
	}
	if err := s.proxy.Apply(); err != nil {
		jsonError(w, 500, "credential saved but proxy activation failed: "+err.Error())
		return
	}
	s.store.AddAudit(actor(r), "update", "access-list-user", strconv.FormatInt(id, 10), username)
	writeJSON(w, 200, map[string]any{"username": username})
}

func (s *Server) accessListUserDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	v, err := s.store.GetAccessList(id)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, 404, "access list not found")
		return
	}
	if err != nil {
		jsonError(w, 500, "cannot read access list")
		return
	}
	username, msg := validateAccessUsername(r.PathValue("username"))
	if msg != "" {
		jsonError(w, 422, msg)
		return
	}
	if strings.TrimSpace(v.AuthFile) == "" {
		jsonError(w, 404, "access-list user not found")
		return
	}
	cmd := exec.Command("htpasswd", "-D", v.AuthFile, username)
	if out, err := cmd.CombinedOutput(); err != nil {
		jsonError(w, 404, "access-list user not found: "+strings.TrimSpace(string(out)))
		return
	}
	users, _ := accessListUsernames(v.AuthFile)
	if len(users) == 0 {
		v.AuthEnabled = false
	}
	_, _ = s.store.UpdateAccessList(id, model.AccessListInput{Name: v.Name, SatisfyAny: v.SatisfyAny, PassAuth: v.PassAuth, AuthEnabled: v.AuthEnabled, Rules: v.Rules, AuthFile: v.AuthFile})
	if err := s.proxy.Apply(); err != nil {
		jsonError(w, 500, "credential removed but proxy activation failed: "+err.Error())
		return
	}
	s.store.AddAudit(actor(r), "delete", "access-list-user", strconv.FormatInt(id, 10), username)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) accessListDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	hosts, _ := s.store.ListHosts()
	for _, h := range hosts {
		if h.AccessListID != nil && *h.AccessListID == id {
			jsonError(w, 409, "access list is still assigned to proxy host "+h.Name)
			return
		}
	}
	if err := s.store.DeleteAccessList(id); err != nil {
		jsonError(w, 500, "cannot delete access list")
		return
	}
	if err := s.proxy.Apply(); err != nil {
		jsonError(w, 500, "access list deleted but proxy activation failed: "+err.Error())
		return
	}
	s.store.AddAudit(actor(r), "delete", "access-list", strconv.FormatInt(id, 10), "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) redirectHostsList(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.ListRedirectHosts()
	if err != nil {
		jsonError(w, 500, "cannot list redirect hosts")
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) redirectHostCreate(w http.ResponseWriter, r *http.Request) {
	var in model.RedirectHostInput
	if err := decodeJSON(r, &in); err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	if len(in.Domains) == 0 || strings.TrimSpace(in.ForwardDomainName) == "" {
		jsonError(w, 422, "domains and forward_domain_name are required")
		return
	}
	if in.ForwardHTTPCode < 300 || in.ForwardHTTPCode > 399 {
		jsonError(w, 422, "forward_http_code must be a 3xx status")
		return
	}
	if in.CertificateID != nil {
		if _, err := s.store.GetCertificate(*in.CertificateID); err != nil {
			jsonError(w, 422, "certificate does not exist")
			return
		}
	}
	v, err := s.store.CreateRedirectHost(in)
	if err != nil {
		jsonError(w, 500, "cannot create redirect host")
		return
	}
	if err := s.proxy.Apply(); err != nil {
		_ = s.store.DeleteRedirectHost(v.ID)
		_ = s.proxy.Apply()
		jsonError(w, 500, "proxy activation failed: "+err.Error())
		return
	}
	s.store.AddAudit(actor(r), "create", "redirect-host", strconv.FormatInt(v.ID, 10), strings.Join(v.Domains, ","))
	writeJSON(w, 201, v)
}
func (s *Server) redirectHostUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	old, err := s.store.GetRedirectHost(id)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, 404, "redirect host not found")
		return
	}
	if err != nil {
		jsonError(w, 500, "cannot read redirect host")
		return
	}
	var in model.RedirectHostInput
	if err := decodeJSON(r, &in); err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	if len(in.Domains) == 0 || strings.TrimSpace(in.ForwardDomainName) == "" {
		jsonError(w, 422, "domains and forward_domain_name are required")
		return
	}
	if in.ForwardHTTPCode < 300 || in.ForwardHTTPCode > 399 {
		jsonError(w, 422, "forward_http_code must be a 3xx status")
		return
	}
	if in.CertificateID != nil {
		if _, err := s.store.GetCertificate(*in.CertificateID); err != nil {
			jsonError(w, 422, "certificate does not exist")
			return
		}
	}
	v, err := s.store.UpdateRedirectHost(id, in)
	if err != nil {
		jsonError(w, 500, "cannot update redirect host")
		return
	}
	if err := s.proxy.Apply(); err != nil {
		_, _ = s.store.UpdateRedirectHost(id, model.RedirectHostInput{Domains: old.Domains, ForwardHTTPCode: old.ForwardHTTPCode, ForwardScheme: old.ForwardScheme, ForwardDomainName: old.ForwardDomainName, PreservePath: old.PreservePath, CertificateID: old.CertificateID, SSLForced: old.SSLForced, HTTP2Support: old.HTTP2Support, HSTSEnabled: old.HSTSEnabled, HSTSSubdomains: old.HSTSSubdomains, BlockExploits: old.BlockExploits, AdvancedConfig: old.AdvancedConfig, Enabled: old.Enabled})
		_ = s.proxy.Apply()
		jsonError(w, 500, "proxy activation failed: "+err.Error())
		return
	}
	s.store.AddAudit(actor(r), "update", "redirect-host", strconv.FormatInt(id, 10), strings.Join(v.Domains, ","))
	writeJSON(w, 200, v)
}
func (s *Server) redirectHostDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteRedirectHost(id); err != nil {
		jsonError(w, 500, "cannot delete redirect host")
		return
	}
	if err := s.proxy.Apply(); err != nil {
		jsonError(w, 500, "redirect host deleted but proxy activation failed: "+err.Error())
		return
	}
	s.store.AddAudit(actor(r), "delete", "redirect-host", strconv.FormatInt(id, 10), "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) deadHostsList(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.ListDeadHosts()
	if err != nil {
		jsonError(w, 500, "cannot list 404 hosts")
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) deadHostCreate(w http.ResponseWriter, r *http.Request) {
	var in model.DeadHostInput
	if err := decodeJSON(r, &in); err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	if len(in.Domains) == 0 {
		jsonError(w, 422, "domains are required")
		return
	}
	if in.CertificateID != nil {
		if _, err := s.store.GetCertificate(*in.CertificateID); err != nil {
			jsonError(w, 422, "certificate does not exist")
			return
		}
	}
	v, err := s.store.CreateDeadHost(in)
	if err != nil {
		jsonError(w, 500, "cannot create 404 host")
		return
	}
	if err := s.proxy.Apply(); err != nil {
		_ = s.store.DeleteDeadHost(v.ID)
		_ = s.proxy.Apply()
		jsonError(w, 500, "proxy activation failed: "+err.Error())
		return
	}
	s.store.AddAudit(actor(r), "create", "dead-host", strconv.FormatInt(v.ID, 10), strings.Join(v.Domains, ","))
	writeJSON(w, 201, v)
}
func (s *Server) deadHostUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	old, err := s.store.GetDeadHost(id)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, 404, "404 host not found")
		return
	}
	if err != nil {
		jsonError(w, 500, "cannot read 404 host")
		return
	}
	var in model.DeadHostInput
	if err := decodeJSON(r, &in); err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	if len(in.Domains) == 0 {
		jsonError(w, 422, "domains are required")
		return
	}
	if in.CertificateID != nil {
		if _, err := s.store.GetCertificate(*in.CertificateID); err != nil {
			jsonError(w, 422, "certificate does not exist")
			return
		}
	}
	v, err := s.store.UpdateDeadHost(id, in)
	if err != nil {
		jsonError(w, 500, "cannot update 404 host")
		return
	}
	if err := s.proxy.Apply(); err != nil {
		_, _ = s.store.UpdateDeadHost(id, model.DeadHostInput{Domains: old.Domains, CertificateID: old.CertificateID, SSLForced: old.SSLForced, HTTP2Support: old.HTTP2Support, HSTSEnabled: old.HSTSEnabled, HSTSSubdomains: old.HSTSSubdomains, AdvancedConfig: old.AdvancedConfig, Enabled: old.Enabled})
		_ = s.proxy.Apply()
		jsonError(w, 500, "proxy activation failed: "+err.Error())
		return
	}
	s.store.AddAudit(actor(r), "update", "dead-host", strconv.FormatInt(id, 10), strings.Join(v.Domains, ","))
	writeJSON(w, 200, v)
}
func (s *Server) deadHostDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteDeadHost(id); err != nil {
		jsonError(w, 500, "cannot delete 404 host")
		return
	}
	if err := s.proxy.Apply(); err != nil {
		jsonError(w, 500, "404 host deleted but proxy activation failed: "+err.Error())
		return
	}
	s.store.AddAudit(actor(r), "delete", "dead-host", strconv.FormatInt(id, 10), "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) streamsList(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.ListStreams()
	if err != nil {
		jsonError(w, 500, "cannot list streams")
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) streamCreate(w http.ResponseWriter, r *http.Request) {
	var in model.StreamInput
	if err := decodeJSON(r, &in); err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	if in.IncomingPort < 1 || in.IncomingPort > 65535 || in.ForwardPort < 1 || in.ForwardPort > 65535 || strings.TrimSpace(in.ForwardHost) == "" || (!in.TCPForwarding && !in.UDPForwarding) {
		jsonError(w, 422, "invalid stream")
		return
	}
	if in.CertificateID != nil {
		if _, err := s.store.GetCertificate(*in.CertificateID); err != nil {
			jsonError(w, 422, "certificate does not exist")
			return
		}
	}
	v, err := s.store.CreateStream(in)
	if err != nil {
		jsonError(w, 500, "cannot create stream")
		return
	}
	if err := s.proxy.Apply(); err != nil {
		_ = s.store.DeleteStream(v.ID)
		_ = s.proxy.Apply()
		jsonError(w, 500, "proxy activation failed: "+err.Error())
		return
	}
	s.store.AddAudit(actor(r), "create", "stream", strconv.FormatInt(v.ID, 10), fmt.Sprintf("%d", v.IncomingPort))
	writeJSON(w, 201, v)
}

func (s *Server) streamUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	old, err := s.store.GetStream(id)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, 404, "stream not found")
		return
	}
	if err != nil {
		jsonError(w, 500, "cannot read stream")
		return
	}
	var in model.StreamInput
	if err := decodeJSON(r, &in); err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	if in.CertificateID != nil {
		if _, err := s.store.GetCertificate(*in.CertificateID); err != nil {
			jsonError(w, 422, "certificate does not exist")
			return
		}
	}
	if in.IncomingPort < 1 || in.IncomingPort > 65535 || in.ForwardPort < 1 || in.ForwardPort > 65535 || strings.TrimSpace(in.ForwardHost) == "" || (!in.TCPForwarding && !in.UDPForwarding) {
		jsonError(w, 422, "invalid stream")
		return
	}
	v, err := s.store.UpdateStream(id, in)
	if err != nil {
		jsonError(w, 500, "cannot update stream")
		return
	}
	if err := s.proxy.Apply(); err != nil {
		_, _ = s.store.UpdateStream(id, model.StreamInput{IncomingPort: old.IncomingPort, ForwardHost: old.ForwardHost, ForwardPort: old.ForwardPort, TCPForwarding: old.TCPForwarding, UDPForwarding: old.UDPForwarding, CertificateID: old.CertificateID, Enabled: old.Enabled})
		_ = s.proxy.Apply()
		jsonError(w, 500, "proxy activation failed: "+err.Error())
		return
	}
	s.store.AddAudit(actor(r), "update", "stream", strconv.FormatInt(id, 10), fmt.Sprintf("%d", v.IncomingPort))
	writeJSON(w, 200, v)
}
func (s *Server) streamDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteStream(id); err != nil {
		jsonError(w, 500, "cannot delete stream")
		return
	}
	if err := s.proxy.Apply(); err != nil {
		jsonError(w, 500, "stream deleted but proxy activation failed: "+err.Error())
		return
	}
	s.store.AddAudit(actor(r), "delete", "stream", strconv.FormatInt(id, 10), "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) certificatesList(w http.ResponseWriter, r *http.Request) {
	v, err := s.certs.List()
	if err != nil {
		jsonError(w, 500, "cannot list certificates")
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) certificateIssue(w http.ResponseWriter, r *http.Request) {
	var in model.CertificateInput
	if err := decodeJSON(r, &in); err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	if strings.TrimSpace(in.Email) == "" {
		in.Email = s.cfg.AdminEmail
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	c, err := s.certs.Issue(ctx, in)
	if err != nil {
		jsonError(w, 502, err.Error())
		return
	}
	s.store.AddAudit(actor(r), "issue", "certificate", strconv.FormatInt(c.ID, 10), c.Name)
	writeJSON(w, 201, c)
}
func (s *Server) certificateImport(w http.ResponseWriter, r *http.Request) {
	var in model.CertificateImportInput
	if err := decodeJSON(r, &in); err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	c, err := s.certs.Import(in)
	if err != nil {
		jsonError(w, 422, err.Error())
		return
	}
	s.store.AddAudit(actor(r), "import", "certificate", strconv.FormatInt(c.ID, 10), c.Name)
	writeJSON(w, 201, c)
}
func (s *Server) certificateUpdateMetadata(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	c, err := s.store.GetCertificate(id)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, 404, "certificate not found")
		return
	}
	if err != nil {
		jsonError(w, 500, "cannot read certificate")
		return
	}
	var in model.CertificateMetadataInput
	if err := decodeJSON(r, &in); err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Description = strings.TrimSpace(in.Description)
	if in.Name == "" {
		jsonError(w, 422, "name is required")
		return
	}
	c.Name = in.Name
	c.Description = in.Description
	c, err = s.store.UpdateCertificate(c)
	if err != nil {
		jsonError(w, 500, "cannot update certificate")
		return
	}
	s.store.AddAudit(actor(r), "update", "certificate", strconv.FormatInt(id, 10), c.Name)
	writeJSON(w, 200, c)
}

func (s *Server) certificateRenew(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	c, err := s.certs.Renew(ctx, id, true)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, 404, "certificate not found")
		return
	}
	if err != nil {
		jsonError(w, 502, err.Error())
		return
	}
	s.store.AddAudit(actor(r), "renew", "certificate", strconv.FormatInt(id, 10), c.Name)
	writeJSON(w, 200, c)
}
func (s *Server) certificateDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	hosts, _ := s.store.ListHosts()
	for _, h := range hosts {
		if h.CertificateID != nil && *h.CertificateID == id {
			jsonError(w, 409, "certificate is still assigned to proxy host "+h.Name)
			return
		}
	}
	redirects, _ := s.store.ListRedirectHosts()
	for _, h := range redirects {
		if h.CertificateID != nil && *h.CertificateID == id {
			jsonError(w, 409, "certificate is still assigned to a redirect host")
			return
		}
	}
	dead, _ := s.store.ListDeadHosts()
	for _, h := range dead {
		if h.CertificateID != nil && *h.CertificateID == id {
			jsonError(w, 409, "certificate is still assigned to a 404 host")
			return
		}
	}
	streams, _ := s.store.ListStreams()
	for _, h := range streams {
		if h.CertificateID != nil && *h.CertificateID == id {
			jsonError(w, 409, "certificate is still assigned to a stream")
			return
		}
	}
	if err := s.certs.Delete(id); errors.Is(err, sql.ErrNoRows) {
		jsonError(w, 404, "certificate not found")
		return
	} else if err != nil {
		jsonError(w, 500, "cannot delete certificate")
		return
	}
	s.store.AddAudit(actor(r), "delete", "certificate", strconv.FormatInt(id, 10), "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func parseSince(r *http.Request) time.Time {
	q := r.URL.Query().Get("range")
	switch q {
	case "1h":
		return time.Now().UTC().Add(-time.Hour)
	case "7d":
		return time.Now().UTC().Add(-7 * 24 * time.Hour)
	case "30d":
		return time.Now().UTC().Add(-30 * 24 * time.Hour)
	default:
		return time.Now().UTC().Add(-24 * time.Hour)
	}
}
func (s *Server) statsSummary(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.StatsSummary(parseSince(r), strings.TrimSpace(r.URL.Query().Get("host")), strings.TrimSpace(r.URL.Query().Get("zentloop")))
	if err != nil {
		jsonError(w, 500, "cannot calculate statistics")
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) statsRequests(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	v, err := s.store.RecentRequests(parseSince(r), strings.TrimSpace(r.URL.Query().Get("host")), strings.TrimSpace(r.URL.Query().Get("zentloop")), limit)
	if err != nil {
		jsonError(w, 500, "cannot load requests")
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) providersList(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.ListProviders()
	if err != nil {
		jsonError(w, 500, "cannot list providers")
		return
	}
	writeJSON(w, 200, v)
}

func normalizeProviderInput(in model.TrustedProxyProviderInput) (model.TrustedProxyProviderInput, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.Header = strings.TrimSpace(in.Header)
	if in.Name == "" {
		return in, fmt.Errorf("name is required")
	}
	if len(in.Name) > 100 {
		return in, fmt.Errorf("name is too long")
	}
	if in.Header == "" || !validHeaderName(in.Header) {
		return in, fmt.Errorf("client IP header is invalid")
	}
	seen := map[string]struct{}{}
	normalized := make([]string, 0, len(in.CIDRs))
	for _, raw := range in.CIDRs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		var value string
		if prefix, err := netip.ParsePrefix(raw); err == nil {
			value = prefix.Masked().String()
		} else if addr, err := netip.ParseAddr(raw); err == nil {
			bits := 128
			if addr.Is4() {
				bits = 32
			}
			value = netip.PrefixFrom(addr, bits).String()
		} else {
			return in, fmt.Errorf("invalid IP address or CIDR: %s", raw)
		}
		if _, ok := seen[value]; !ok {
			seen[value] = struct{}{}
			normalized = append(normalized, value)
		}
	}
	if len(normalized) == 0 {
		return in, fmt.Errorf("at least one trusted IP address or CIDR is required")
	}
	if len(normalized) > 5000 {
		return in, fmt.Errorf("too many trusted IP ranges")
	}
	sort.Strings(normalized)
	in.CIDRs = normalized
	return in, nil
}

func validHeaderName(v string) bool {
	if v == "" {
		return false
	}
	for _, c := range v {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", c) {
			continue
		}
		return false
	}
	return true
}

func (s *Server) providerCreate(w http.ResponseWriter, r *http.Request) {
	var in model.TrustedProxyProviderInput
	if err := decodeJSON(r, &in); err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	in, err := normalizeProviderInput(in)
	if err != nil {
		jsonError(w, 422, err.Error())
		return
	}
	slug := "custom-" + strconv.FormatInt(time.Now().UTC().UnixNano(), 36)
	p, err := s.store.CreateProvider(slug, in)
	if err != nil {
		jsonError(w, 500, "cannot create provider")
		return
	}
	s.store.AddAudit(actor(r), "create", "trusted-proxy-provider", strconv.FormatInt(p.ID, 10), p.Name)
	writeJSON(w, 201, p)
}

func (s *Server) providerUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	existing, err := s.store.GetProvider(id)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, 404, "provider not found")
		return
	}
	if err != nil {
		jsonError(w, 500, "cannot load provider")
		return
	}
	if existing.Kind != "manual" {
		jsonError(w, 409, "built-in provider cannot be edited")
		return
	}
	var in model.TrustedProxyProviderInput
	if err := decodeJSON(r, &in); err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	in, err = normalizeProviderInput(in)
	if err != nil {
		jsonError(w, 422, err.Error())
		return
	}
	p, err := s.store.UpdateProvider(id, in)
	if err != nil {
		jsonError(w, 500, "cannot update provider")
		return
	}
	if err := s.proxy.Apply(); err != nil {
		jsonError(w, 500, "provider saved but proxy reload failed: "+err.Error())
		return
	}
	s.store.AddAudit(actor(r), "update", "trusted-proxy-provider", strconv.FormatInt(id, 10), p.Name)
	writeJSON(w, 200, p)
}

func (s *Server) providerDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p, err := s.store.GetProvider(id)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, 404, "provider not found")
		return
	}
	if err != nil {
		jsonError(w, 500, "cannot load provider")
		return
	}
	if p.Kind != "manual" {
		jsonError(w, 409, "built-in provider cannot be deleted")
		return
	}
	affected, err := s.store.DeleteProvider(id)
	if err != nil {
		jsonError(w, 500, "cannot delete provider")
		return
	}
	if err := s.proxy.Apply(); err != nil {
		jsonError(w, 500, "provider deleted but proxy reload failed: "+err.Error())
		return
	}
	detail := p.Name
	if affected > 0 {
		detail = fmt.Sprintf("%s · %d host(s) reset to Direct / None", p.Name, affected)
	}
	s.store.AddAudit(actor(r), "delete", "trusted-proxy-provider", strconv.FormatInt(id, 10), detail)
	writeJSON(w, 200, map[string]any{"deleted": true, "hosts_reset": affected})
}
func (s *Server) providerRefresh(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p, err := s.providers.Refresh(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, 404, "provider not found")
		return
	}
	if err != nil {
		jsonError(w, 502, err.Error())
		return
	}
	s.store.AddAudit(actor(r), "refresh", "trusted-proxy-provider", strconv.FormatInt(id, 10), p.Name)
	writeJSON(w, 200, p)
}

func (s *Server) zentLoopGet(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.GetZentLoop()
	if err != nil {
		jsonError(w, 500, "cannot load integration")
		return
	}
	if cfg.Secret != "" {
		cfg.Secret = "********"
	}
	health := zentloop.Health{Status: "unknown", Verification: "unknown"}
	if s.zentLoop != nil {
		health = s.zentLoop.Snapshot()
	}
	writeJSON(w, 200, map[string]any{"enabled": cfg.Enabled, "forward_unknown_hosts": cfg.ForwardUnknownHosts, "upstream": cfg.Upstream, "secret": cfg.Secret, "fallback": cfg.Fallback, "ip_lists": cfg.IPLists, "rules": cfg.Rules, "health": health})
}
func (s *Server) zentLoopSet(w http.ResponseWriter, r *http.Request) {
	old, err := s.store.GetZentLoop()
	if err != nil {
		jsonError(w, 500, "cannot load integration")
		return
	}
	var in model.ZentLoopConfig
	if err := decodeJSON(r, &in); err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	in.Upstream = strings.TrimSpace(in.Upstream)
	in.Fallback = strings.ToLower(strings.TrimSpace(in.Fallback))
	if in.Fallback != "503" {
		in.Fallback = "block"
	}
	// When the integration is disabled the advanced editors are intentionally hidden in the UI.
	// Preserve their saved values instead of treating missing DOM fields as deletion requests.
	if !in.Enabled {
		if in.Upstream == "" {
			in.Upstream = old.Upstream
		}
		if len(in.IPLists) == 0 {
			in.IPLists = old.IPLists
		}
		if len(in.Rules) == 0 {
			in.Rules = old.Rules
		}
	}
	listNames := map[string]bool{}
	for i := range in.IPLists {
		in.IPLists[i].Name = strings.TrimSpace(in.IPLists[i].Name)
		if in.IPLists[i].Name == "" || listNames[strings.ToLower(in.IPLists[i].Name)] {
			jsonError(w, 422, "ZentLoop IP list names must be unique and non-empty")
			return
		}
		listNames[strings.ToLower(in.IPLists[i].Name)] = true
		clean := make([]string, 0, len(in.IPLists[i].Entries))
		for _, raw := range in.IPLists[i].Entries {
			v := strings.TrimSpace(raw)
			if v == "" {
				continue
			}
			if _, err := netip.ParsePrefix(v); err != nil {
				if _, err2 := netip.ParseAddr(v); err2 != nil {
					jsonError(w, 422, "invalid IP/CIDR in ZentLoop list: "+v)
					return
				}
			}
			clean = append(clean, v)
		}
		in.IPLists[i].Entries = clean
	}
	for i := range in.Rules {
		r := &in.Rules[i]
		r.Name = strings.TrimSpace(r.Name)
		r.Match = strings.ToLower(strings.TrimSpace(r.Match))
		r.Value = strings.TrimSpace(r.Value)
		r.Action = strings.ToLower(strings.TrimSpace(r.Action))
		if r.Name == "" || r.Value == "" {
			jsonError(w, 422, "ZentLoop rules require a name and value")
			return
		}
		if r.Match != "source_ip_list" && r.Match != "path_exact" && r.Match != "path_prefix" {
			jsonError(w, 422, "unsupported ZentLoop rule match")
			return
		}
		if r.Action != "zentloop" && r.Action != "block" {
			jsonError(w, 422, "ZentLoop rule action must be zentloop or block")
			return
		}
		if r.Match == "source_ip_list" && !listNames[strings.ToLower(r.Value)] {
			jsonError(w, 422, "ZentLoop rule references an unknown IP list: "+r.Value)
			return
		}
		if r.Match != "source_ip_list" && (!strings.HasPrefix(r.Value, "/") || strings.ContainsAny(r.Value, " \t\r\n{};")) {
			jsonError(w, 422, "ZentLoop path rules must start with / and contain no directives")
			return
		}
	}
	if in.Upstream == "" {
		in.Upstream = "http://zentloop:8080"
	}
	u, err := url.Parse(in.Upstream)
	if in.Enabled && (err != nil || !(u.Scheme == "http" || u.Scheme == "https") || u.Host == "" || u.User != nil) {
		jsonError(w, 422, "upstream must be a valid http:// or https:// URL without embedded credentials")
		return
	}
	if in.Secret == "********" {
		in.Secret = old.Secret
	}
	if err := s.store.SetZentLoop(in); err != nil {
		jsonError(w, 500, "cannot save integration")
		return
	}
	if err := s.proxy.Apply(); err != nil {
		_ = s.store.SetZentLoop(old)
		_ = s.proxy.Apply()
		jsonError(w, 500, "integration update was rolled back because proxy reload failed: "+err.Error())
		return
	}
	if s.zentLoop != nil {
		s.zentLoop.CheckNow(r.Context())
	}
	s.store.AddAudit(actor(r), "update", "integration", "zentloop", fmt.Sprintf("enabled=%v forward_unknown_hosts=%v upstream=%s", in.Enabled, in.ForwardUnknownHosts, in.Upstream))
	out := in
	if out.Secret != "" {
		out.Secret = "********"
	}
	health := zentloop.Health{Status: "unknown", Verification: "unknown"}
	if s.zentLoop != nil {
		health = s.zentLoop.Snapshot()
	}
	writeJSON(w, 200, map[string]any{"enabled": out.Enabled, "forward_unknown_hosts": out.ForwardUnknownHosts, "upstream": out.Upstream, "secret": out.Secret, "fallback": out.Fallback, "ip_lists": out.IPLists, "rules": out.Rules, "health": health})
}

func (s *Server) zentLoopCheck(w http.ResponseWriter, r *http.Request) {
	if s.zentLoop == nil {
		jsonError(w, 503, "ZentLoop monitor is not available")
		return
	}
	health := s.zentLoop.CheckNow(r.Context())
	writeJSON(w, 200, health)
}

func (s *Server) apiKeysList(w http.ResponseWriter, r *http.Request) {
	v, err := s.store.ListAPIKeys()
	if err != nil {
		jsonError(w, 500, "cannot list API keys")
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) apiKeysCreate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
	}
	if err := decodeJSON(r, &in); err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 100 {
		jsonError(w, 422, "name is required")
		return
	}
	allowed := map[string]bool{}
	for _, v := range allowedScopes {
		allowed[v] = true
	}
	seen := map[string]bool{}
	var scopes []string
	for _, scope := range in.Scopes {
		scope = strings.TrimSpace(scope)
		if !allowed[scope] {
			jsonError(w, 422, "unknown scope: "+scope)
			return
		}
		if !seen[scope] {
			seen[scope] = true
			scopes = append(scopes, scope)
		}
	}
	if len(scopes) == 0 {
		jsonError(w, 422, "at least one scope is required")
		return
	}
	k, token, err := s.store.CreateAPIKey(in.Name, scopes)
	if err != nil {
		jsonError(w, 500, "cannot create API key")
		return
	}
	s.store.AddAudit(actor(r), "create", "api-key", strconv.FormatInt(k.ID, 10), k.Name)
	writeJSON(w, 201, map[string]any{"key": k, "token": token, "warning": "The token is shown only once."})
}
func (s *Server) apiKeyRevoke(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.store.RevokeAPIKey(id); errors.Is(err, sql.ErrNoRows) {
		jsonError(w, 404, "API key not found or already revoked")
		return
	} else if err != nil {
		jsonError(w, 500, "cannot revoke API key")
		return
	}
	s.store.AddAudit(actor(r), "revoke", "api-key", strconv.FormatInt(id, 10), "")
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	v, err := s.store.Audit(limit)
	if err != nil {
		jsonError(w, 500, "cannot load audit log")
		return
	}
	writeJSON(w, 200, v)
}

func (s *Server) migrationAnalyze(w http.ResponseWriter, r *http.Request) {
	var creds migration.Credentials
	if err := decodeJSON(r, &creds); err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	existing, err := s.store.ListHosts()
	if err != nil {
		jsonError(w, 500, "cannot load existing hosts")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	analysis, err := migration.Analyze(ctx, creds, existing)
	if err != nil {
		jsonError(w, 502, "migration analysis failed: "+err.Error())
		return
	}
	s.store.AddAudit(actor(r), "analyze", "migration", "", analysis.Source.URL)
	writeJSON(w, 200, analysis)
}

func (s *Server) migrationImport(w http.ResponseWriter, r *http.Request) {
	if !s.migrationMu.TryLock() {
		jsonError(w, 409, "a migration import is already running")
		return
	}
	defer s.migrationMu.Unlock()
	var in struct {
		migration.Credentials
		SourceIDs []int64 `json:"source_ids"`
	}
	if err := decodeJSON(r, &in); err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	existing, err := s.store.ListHosts()
	if err != nil {
		jsonError(w, 500, "cannot load existing hosts")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()
	batch, err := migration.PrepareBatch(ctx, in.Credentials, existing, in.SourceIDs)
	if err != nil {
		jsonError(w, 422, "migration cannot start: "+err.Error())
		return
	}

	certMap := map[int64]int64{}
	failedCerts := map[int64]string{}
	certificateErrors := []string{}
	accessMap := map[int64]int64{}
	certIDs := []int64{}
	createdCertIDs := []int64{}
	accessIDs := []int64{}
	redirectIDs := []int64{}
	deadIDs := []int64{}
	streamIDs := []int64{}
	hostIDs := []int64{}
	authFiles := []string{}
	rollback := func() {
		_ = s.store.DeleteHosts(hostIDs)
		for i := len(streamIDs) - 1; i >= 0; i-- {
			_ = s.store.DeleteStream(streamIDs[i])
		}
		for i := len(deadIDs) - 1; i >= 0; i-- {
			_ = s.store.DeleteDeadHost(deadIDs[i])
		}
		for i := len(redirectIDs) - 1; i >= 0; i-- {
			_ = s.store.DeleteRedirectHost(redirectIDs[i])
		}
		for i := len(accessIDs) - 1; i >= 0; i-- {
			_ = s.store.DeleteAccessList(accessIDs[i])
		}
		for _, f := range authFiles {
			_ = os.Remove(f)
		}
		for i := len(createdCertIDs) - 1; i >= 0; i-- {
			_ = s.certs.Delete(createdCertIDs[i])
		}
		_ = s.proxy.Apply()
	}
	fail := func(status int, msg string) { rollback(); jsonError(w, status, msg) }

	for _, cp := range batch.Certificates {
		var c model.Certificate
		if cp.Reissue {
			c, err = s.certs.Issue(ctx, model.CertificateInput{
				Name: cp.Input.Name, Domains: cp.Input.Domains, Challenge: cp.Input.Challenge,
				Email: cp.Input.Email, DNSProvider: cp.Input.DNSProvider,
				DNSCredentials: cp.Input.DNSCredentials, AutoRenew: cp.Input.AutoRenew,
			})
		} else {
			c, err = s.certs.Import(cp.Input)
		}
		if err != nil {
			if c.ID > 0 {
				createdCertIDs = append(createdCertIDs, c.ID)
			}
			if cp.Reissue {
				msg := fmt.Sprintf("Let's Encrypt certificate %s could not be issued during migration: %v", cp.Name, err)
				failedCerts[cp.SourceID] = msg
				certificateErrors = append(certificateErrors, msg)
				batch.Warnings = append(batch.Warnings, msg+". Dependent routing objects were imported without TLS and can be issued/relinked later.")
				continue
			}
			fail(422, fmt.Sprintf("certificate %s could not be imported: %v", cp.Name, err))
			return
		}
		certMap[cp.SourceID] = c.ID
		certIDs = append(certIDs, c.ID)
		createdCertIDs = append(createdCertIDs, c.ID)
	}
	for _, ap := range batch.AccessLists {
		input := ap.Input
		input.AuthFile = ""
		a, err := s.store.CreateAccessList(input)
		if err != nil {
			fail(500, "cannot import access list "+ap.Name)
			return
		}
		accessMap[ap.SourceID] = a.ID
		accessIDs = append(accessIDs, a.ID)
		if ap.AuthSource != "" {
			dst := filepath.Join(s.cfg.DataDir, "access-lists", strconv.FormatInt(a.ID, 10)+".htpasswd")
			if err := copyMigrationFile(ap.AuthSource, dst, 0o600); err != nil {
				fail(422, fmt.Sprintf("Basic Auth data for %s could not be copied: %v", ap.Name, err))
				return
			}
			authFiles = append(authFiles, dst)
			input.AuthFile = dst
			if _, err := s.store.UpdateAccessList(a.ID, input); err != nil {
				fail(500, "cannot finalize access list "+ap.Name)
				return
			}
		}
	}
	mapCert := func(sourceID int64) (*int64, error) {
		if sourceID < 1 {
			return nil, nil
		}
		id, ok := certMap[sourceID]
		if ok {
			return &id, nil
		}
		if _, failed := failedCerts[sourceID]; failed {
			return nil, nil
		}
		return nil, fmt.Errorf("required certificate %d is missing", sourceID)
	}
	disableTLS := func(sourceID int64, sslForced, http2, hsts, hstsSubdomains *bool) {
		if _, failed := failedCerts[sourceID]; !failed {
			return
		}
		*sslForced = false
		*http2 = false
		*hsts = false
		*hstsSubdomains = false
	}
	for _, rp := range batch.Redirects {
		input := rp.Input
		input.CertificateID, err = mapCert(rp.SourceCertificateID)
		disableTLS(rp.SourceCertificateID, &input.SSLForced, &input.HTTP2Support, &input.HSTSEnabled, &input.HSTSSubdomains)
		if err != nil {
			fail(422, err.Error())
			return
		}
		v, e := s.store.CreateRedirectHost(input)
		if e != nil {
			fail(500, "cannot import redirect host")
			return
		}
		redirectIDs = append(redirectIDs, v.ID)
	}
	for _, dp := range batch.DeadHosts {
		input := dp.Input
		input.CertificateID, err = mapCert(dp.SourceCertificateID)
		disableTLS(dp.SourceCertificateID, &input.SSLForced, &input.HTTP2Support, &input.HSTSEnabled, &input.HSTSSubdomains)
		if err != nil {
			fail(422, err.Error())
			return
		}
		v, e := s.store.CreateDeadHost(input)
		if e != nil {
			fail(500, "cannot import 404 host")
			return
		}
		deadIDs = append(deadIDs, v.ID)
	}
	for _, sp := range batch.Streams {
		input := sp.Input
		input.CertificateID, err = mapCert(sp.SourceCertificateID)
		if err != nil {
			fail(422, err.Error())
			return
		}
		v, e := s.store.CreateStream(input)
		if e != nil {
			fail(500, "cannot import stream")
			return
		}
		streamIDs = append(streamIDs, v.ID)
	}
	inputs := make([]model.HostInput, 0, len(batch.Hosts))
	for _, hp := range batch.Hosts {
		input := hp.Input
		input.CertificateID, err = mapCert(hp.SourceCertificateID)
		disableTLS(hp.SourceCertificateID, &input.SSLForced, &input.HTTP2Support, &input.HSTSEnabled, &input.HSTSSubdomains)
		if err != nil {
			fail(422, err.Error())
			return
		}
		if hp.SourceAccessListID > 0 {
			id, ok := accessMap[hp.SourceAccessListID]
			if !ok {
				fail(422, "required access list mapping is missing")
				return
			}
			input.AccessListID = &id
		}
		inputs = append(inputs, input)
	}
	if len(inputs) > 0 {
		hostIDs, err = s.store.CreateHosts(inputs)
		if err != nil {
			fail(500, "cannot write imported proxy hosts")
			return
		}
	}
	if err := s.proxy.Apply(); err != nil {
		fail(500, "imported configuration was rolled back because proxy activation failed: "+err.Error())
		return
	}

	for i, id := range hostIDs {
		name := ""
		if i < len(inputs) {
			name = inputs[i].Name
		}
		s.store.AddAudit(actor(r), "import", "host", strconv.FormatInt(id, 10), name)
	}
	for _, id := range certIDs {
		s.store.AddAudit(actor(r), "import", "certificate", strconv.FormatInt(id, 10), "migration")
	}
	for _, id := range accessIDs {
		s.store.AddAudit(actor(r), "import", "access-list", strconv.FormatInt(id, 10), "migration")
	}
	for _, id := range redirectIDs {
		s.store.AddAudit(actor(r), "import", "redirect-host", strconv.FormatInt(id, 10), "migration")
	}
	for _, id := range deadIDs {
		s.store.AddAudit(actor(r), "import", "dead-host", strconv.FormatInt(id, 10), "migration")
	}
	for _, id := range streamIDs {
		s.store.AddAudit(actor(r), "import", "stream", strconv.FormatInt(id, 10), "migration")
	}
	skipped := 0
	if len(in.SourceIDs) > len(hostIDs) {
		skipped = len(in.SourceIDs) - len(hostIDs)
	}
	writeJSON(w, 201, migration.ImportResult{Imported: len(hostIDs), ImportedCertificates: len(certIDs), ImportedAccessLists: len(accessIDs), ImportedRedirects: len(redirectIDs), ImportedDeadHosts: len(deadIDs), ImportedStreams: len(streamIDs), Skipped: skipped, HostIDs: hostIDs, CertificateIDs: certIDs, AccessListIDs: accessIDs, RedirectIDs: redirectIDs, DeadHostIDs: deadIDs, StreamIDs: streamIDs, Warnings: batch.Warnings, FailedCertificates: len(certificateErrors), CertificateErrors: certificateErrors})
}

func copyMigrationFile(src, dst string, mode os.FileMode) error {
	clean := filepath.Clean(src)
	if !strings.HasPrefix(clean, filepath.Clean("/migration/data")+string(os.PathSeparator)) {
		return errors.New("source auth path is outside the read-only migration mount")
	}
	raw, err := os.ReadFile(clean)
	if err != nil {
		return err
	}
	if len(raw) > 8<<20 {
		return errors.New("source auth file is unexpectedly large")
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	return os.WriteFile(dst, raw, mode)
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		jsonError(w, 400, "invalid id")
		return 0, false
	}
	return id, true
}
func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, (1<<20)+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("request body must contain one JSON object")
	}
	return nil
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func jsonError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg, "status": status})
}
