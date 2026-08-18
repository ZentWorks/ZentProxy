package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ZentWorks/ZentProxy/internal/auth"
	"github.com/ZentWorks/ZentProxy/internal/model"
	_ "github.com/ZentWorks/ZentProxy/internal/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, err
	}
	path := filepath.Join(dataDir, "zentproxy.db")
	db, err := sql.Open("zsqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, q := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
	} {
		if _, err := db.Exec(q); err != nil {
			db.Close()
			return nil, err
		}
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.seed(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  language TEXT NOT NULL DEFAULT 'en',
  proxy_hosts_view TEXT NOT NULL DEFAULT 'list',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  csrf_token TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  prefix TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  scopes_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_used TEXT,
  revoked_at TEXT
);
CREATE TABLE IF NOT EXISTS trusted_proxy_providers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  kind TEXT NOT NULL,
  real_ip_header TEXT NOT NULL,
  auto_update INTEGER NOT NULL DEFAULT 0,
  source_ipv4 TEXT NOT NULL DEFAULT '',
  source_ipv6 TEXT NOT NULL DEFAULT '',
  cidrs_json TEXT NOT NULL DEFAULT '[]',
  last_checked TEXT,
  last_changed TEXT,
  last_error TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS certificates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  provider TEXT NOT NULL,
  domains_json TEXT NOT NULL,
  challenge TEXT NOT NULL DEFAULT 'http-01',
  email TEXT NOT NULL DEFAULT '',
  dns_provider TEXT NOT NULL DEFAULT '',
  auto_renew INTEGER NOT NULL DEFAULT 0,
  cert_path TEXT NOT NULL DEFAULT '',
  key_path TEXT NOT NULL DEFAULT '',
  expires_at TEXT,
  last_renewed TEXT,
  last_error TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS access_lists (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  satisfy_any INTEGER NOT NULL DEFAULT 0,
  pass_auth INTEGER NOT NULL DEFAULT 0,
  auth_enabled INTEGER NOT NULL DEFAULT 0,
  rules_json TEXT NOT NULL DEFAULT '[]',
  auth_file TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hosts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  domains_json TEXT NOT NULL,
  scheme TEXT NOT NULL,
  forward_host TEXT NOT NULL,
  forward_port INTEGER NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  websockets INTEGER NOT NULL DEFAULT 1,
  preserve_host INTEGER NOT NULL DEFAULT 1,
  statistics_enabled INTEGER NOT NULL DEFAULT 1,
  store_query_string INTEGER NOT NULL DEFAULT 0,
  trusted_proxy_provider_id INTEGER REFERENCES trusted_proxy_providers(id) ON DELETE SET NULL,
  access_list_id INTEGER REFERENCES access_lists(id) ON DELETE SET NULL,
  block_common_exploits INTEGER NOT NULL DEFAULT 0,
  certificate_id INTEGER REFERENCES certificates(id) ON DELETE SET NULL,
  ssl_forced INTEGER NOT NULL DEFAULT 0,
  http2_support INTEGER NOT NULL DEFAULT 0,
  hsts_enabled INTEGER NOT NULL DEFAULT 0,
  hsts_subdomains INTEGER NOT NULL DEFAULT 0,
  caching_enabled INTEGER NOT NULL DEFAULT 0,
  trust_forwarded_proto INTEGER NOT NULL DEFAULT 0,
  advanced_config TEXT NOT NULL DEFAULT '',
  custom_locations_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS redirect_hosts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domains_json TEXT NOT NULL,
  forward_http_code INTEGER NOT NULL,
  forward_scheme TEXT NOT NULL,
  forward_domain_name TEXT NOT NULL,
  preserve_path INTEGER NOT NULL DEFAULT 1,
  certificate_id INTEGER REFERENCES certificates(id) ON DELETE SET NULL,
  ssl_forced INTEGER NOT NULL DEFAULT 0,
  http2_support INTEGER NOT NULL DEFAULT 0,
  hsts_enabled INTEGER NOT NULL DEFAULT 0,
  hsts_subdomains INTEGER NOT NULL DEFAULT 0,
  block_exploits INTEGER NOT NULL DEFAULT 0,
  advanced_config TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dead_hosts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domains_json TEXT NOT NULL,
  certificate_id INTEGER REFERENCES certificates(id) ON DELETE SET NULL,
  ssl_forced INTEGER NOT NULL DEFAULT 0,
  http2_support INTEGER NOT NULL DEFAULT 0,
  hsts_enabled INTEGER NOT NULL DEFAULT 0,
  hsts_subdomains INTEGER NOT NULL DEFAULT 0,
  advanced_config TEXT NOT NULL DEFAULT '',
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS streams (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incoming_port INTEGER NOT NULL,
  forward_host TEXT NOT NULL,
  forward_port INTEGER NOT NULL,
  tcp_forwarding INTEGER NOT NULL DEFAULT 1,
  udp_forwarding INTEGER NOT NULL DEFAULT 0,
  certificate_id INTEGER REFERENCES certificates(id) ON DELETE SET NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS integration_settings (
  slug TEXT PRIMARY KEY,
  config_json TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS analytics_state (
  name TEXT PRIMARY KEY,
  offset INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS raw_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  host TEXT NOT NULL,
  ip TEXT NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  query TEXT NOT NULL DEFAULT '',
  status INTEGER NOT NULL,
  bytes INTEGER NOT NULL,
  request_time_ms REAL NOT NULL,
  upstream_time_ms REAL,
  user_agent TEXT NOT NULL DEFAULT '',
  referer TEXT NOT NULL DEFAULT '',
  http_version TEXT NOT NULL DEFAULT '',
  tls_version TEXT NOT NULL DEFAULT '',
  zentloop INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_raw_requests_at ON raw_requests(at);
CREATE INDEX IF NOT EXISTS idx_raw_requests_host_at ON raw_requests(host, at);
CREATE INDEX IF NOT EXISTS idx_raw_requests_ip_at ON raw_requests(ip, at);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  object_type TEXT NOT NULL,
  object_id TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_log_at ON audit_log(at);
`
	for _, statement := range strings.Split(schema, ";") {
		statement = strings.TrimSpace(statement)
		if statement == "" {
			continue
		}
		if _, err := s.db.Exec(statement); err != nil {
			return fmt.Errorf("schema migration failed: %w", err)
		}
	}
	// 0.2 adds native TLS fields to databases created by older ZentProxy versions.
	if err := s.ensureColumn("users", "language", "TEXT NOT NULL DEFAULT 'en'"); err != nil {
		return err
	}
	if err := s.ensureColumn("users", "proxy_hosts_view", "TEXT NOT NULL DEFAULT 'list'"); err != nil {
		return err
	}
	if err := s.ensureColumn("certificates", "description", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := s.ensureColumn("raw_requests", "zentloop", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	hadAccessAuthEnabled, err := s.columnExists("access_lists", "auth_enabled")
	if err != nil {
		return err
	}
	if err := s.ensureColumn("access_lists", "auth_enabled", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if !hadAccessAuthEnabled {
		if _, err := s.db.Exec(`UPDATE access_lists SET auth_enabled=1 WHERE TRIM(auth_file)<>''`); err != nil {
			return fmt.Errorf("schema migration enable existing access-list auth: %w", err)
		}
	}
	for name, definition := range map[string]string{
		"certificate_id": "INTEGER REFERENCES certificates(id) ON DELETE SET NULL",
		"access_list_id": "INTEGER REFERENCES access_lists(id) ON DELETE SET NULL",
		"ssl_forced":     "INTEGER NOT NULL DEFAULT 0", "http2_support": "INTEGER NOT NULL DEFAULT 0",
		"hsts_enabled": "INTEGER NOT NULL DEFAULT 0", "hsts_subdomains": "INTEGER NOT NULL DEFAULT 0",
		"caching_enabled": "INTEGER NOT NULL DEFAULT 0", "trust_forwarded_proto": "INTEGER NOT NULL DEFAULT 0",
		"advanced_config": "TEXT NOT NULL DEFAULT ''", "custom_locations_json": "TEXT NOT NULL DEFAULT '[]'",
	} {
		if err := s.ensureColumn("hosts", name, definition); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) columnExists(table, column string) (bool, error) {
	rows, err := s.db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var def any
		if err := rows.Scan(&cid, &name, &typ, &notnull, &def, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

func (s *Store) ensureColumn(table, column, definition string) error {
	rows, err := s.db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return err
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var def any
		if err := rows.Scan(&cid, &name, &typ, &notnull, &def, &pk); err != nil {
			return err
		}
		if name == column {
			found = true
			break
		}
	}
	if found {
		return nil
	}
	if _, err := s.db.Exec("ALTER TABLE " + table + " ADD COLUMN " + column + " " + definition); err != nil {
		return fmt.Errorf("schema migration add %s.%s failed: %w", table, column, err)
	}
	return nil
}

func (s *Store) seed() error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.Exec(`INSERT INTO trusted_proxy_providers
		(slug,name,kind,real_ip_header,auto_update,source_ipv4,source_ipv6,cidrs_json,last_error)
		VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(slug) DO NOTHING`,
		"cloudflare", "Cloudflare", "remote", "CF-Connecting-IP", 1,
		"https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6", "[]", "")
	if err != nil {
		return err
	}
	// ZentLoop is currently the single supported integration. Preserve the most recent
	// existing integration configuration during upgrades without retaining obsolete slugs.
	_, err = s.db.Exec(`INSERT INTO integration_settings(slug,config_json,updated_at)
		SELECT 'zentloop',config_json,updated_at FROM integration_settings
		WHERE slug <> 'zentloop' ORDER BY updated_at DESC LIMIT 1
		ON CONFLICT(slug) DO NOTHING`)
	if err != nil {
		return err
	}
	defaultZentLoop, _ := json.Marshal(model.ZentLoopConfig{Enabled: false, Upstream: "http://zentloop:8080", Fallback: "block"})
	_, err = s.db.Exec(`INSERT INTO integration_settings(slug,config_json,updated_at) VALUES(?,?,?) ON CONFLICT(slug) DO NOTHING`, "zentloop", string(defaultZentLoop), now)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`DELETE FROM integration_settings WHERE slug <> 'zentloop'`)
	return err
}

func (s *Store) UserCount() (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	return count, err
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func (s *Store) EnsureAdmin(email, password string) (generatedPassword string, err error) {
	email = normalizeEmail(email)
	count, err := s.UserCount()
	if err != nil {
		return "", err
	}
	if count > 0 {
		// 0.4 migrates the single legacy username-style bootstrap account to the
		// configured administrator e-mail. Existing e-mail identities are left alone.
		if count == 1 && email != "" {
			var id int64
			var current string
			if qerr := s.db.QueryRow(`SELECT id,username FROM users LIMIT 1`).Scan(&id, &current); qerr == nil && !strings.Contains(current, "@") {
				if _, qerr = s.db.Exec(`UPDATE users SET username=? WHERE id=?`, email, id); qerr != nil {
					return "", qerr
				}
			}
		}
		return "", nil
	}
	if strings.TrimSpace(password) == "" {
		password, err = auth.RandomToken(18)
		if err != nil {
			return "", err
		}
		generatedPassword = password
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return "", err
	}
	_, err = s.db.Exec(`INSERT INTO users(username,password_hash,created_at) VALUES(?,?,?)`, email, hash, time.Now().UTC().Format(time.RFC3339Nano))
	return generatedPassword, err
}

func (s *Store) Authenticate(username, password string) (int64, bool, error) {
	var id int64
	var hash string
	username = strings.ToLower(strings.TrimSpace(username))
	err := s.db.QueryRow(`SELECT id,password_hash FROM users WHERE LOWER(username)=?`, username).Scan(&id, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return id, auth.VerifyPassword(hash, password), nil
}

func (s *Store) CreateSession(userID int64, ttl time.Duration) (token, csrf string, expires time.Time, err error) {
	token, err = auth.RandomToken(32)
	if err != nil {
		return
	}
	csrf, err = auth.RandomToken(24)
	if err != nil {
		return
	}
	expires = time.Now().UTC().Add(ttl)
	_, err = s.db.Exec(`INSERT INTO sessions(token_hash,user_id,csrf_token,expires_at,created_at) VALUES(?,?,?,?,?)`,
		auth.TokenHash(token), userID, csrf, expires.Format(time.RFC3339Nano), time.Now().UTC().Format(time.RFC3339Nano))
	return
}

func (s *Store) ValidateSession(token string) (userID int64, csrf string, ok bool, err error) {
	var expiresRaw string
	err = s.db.QueryRow(`SELECT user_id,csrf_token,expires_at FROM sessions WHERE token_hash=?`, auth.TokenHash(token)).Scan(&userID, &csrf, &expiresRaw)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", false, nil
	}
	if err != nil {
		return 0, "", false, err
	}
	expires, parseErr := time.Parse(time.RFC3339Nano, expiresRaw)
	if parseErr != nil || time.Now().UTC().After(expires) {
		_, _ = s.db.Exec(`DELETE FROM sessions WHERE token_hash=?`, auth.TokenHash(token))
		return 0, "", false, nil
	}
	return userID, csrf, true, nil
}

func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token_hash=?`, auth.TokenHash(token))
	return err
}

func (s *Store) Username(userID int64) string {
	var username string
	_ = s.db.QueryRow(`SELECT username FROM users WHERE id=?`, userID).Scan(&username)
	return username
}

func (s *Store) UserLanguage(userID int64) string {
	var language string
	_ = s.db.QueryRow(`SELECT language FROM users WHERE id=?`, userID).Scan(&language)
	language = strings.ToLower(strings.TrimSpace(language))
	if language != "de" && language != "en" {
		return "en"
	}
	return language
}

func (s *Store) UserProxyHostsView(userID int64) string {
	var view string
	_ = s.db.QueryRow(`SELECT proxy_hosts_view FROM users WHERE id=?`, userID).Scan(&view)
	view = strings.ToLower(strings.TrimSpace(view))
	if view != "grouped" {
		return "list"
	}
	return view
}

func (s *Store) SetUserProxyHostsView(userID int64, view string) error {
	view = strings.ToLower(strings.TrimSpace(view))
	if view != "list" && view != "grouped" {
		return fmt.Errorf("unsupported proxy hosts view")
	}
	res, err := s.db.Exec(`UPDATE users SET proxy_hosts_view=? WHERE id=?`, view, userID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) SetUserLanguage(userID int64, language string) error {
	language = strings.ToLower(strings.TrimSpace(language))
	if language != "de" && language != "en" {
		return fmt.Errorf("unsupported language")
	}
	res, err := s.db.Exec(`UPDATE users SET language=? WHERE id=?`, language, userID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) ListHosts() ([]model.Host, error) {
	rows, err := s.db.Query(`SELECT id,name,domains_json,scheme,forward_host,forward_port,enabled,websockets,preserve_host,statistics_enabled,store_query_string,trusted_proxy_provider_id,access_list_id,block_common_exploits,certificate_id,ssl_forced,http2_support,hsts_enabled,hsts_subdomains,caching_enabled,trust_forwarded_proto,advanced_config,custom_locations_json,created_at,updated_at FROM hosts ORDER BY name COLLATE NOCASE, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Host{}
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) GetHost(id int64) (model.Host, error) {
	row := s.db.QueryRow(`SELECT id,name,domains_json,scheme,forward_host,forward_port,enabled,websockets,preserve_host,statistics_enabled,store_query_string,trusted_proxy_provider_id,access_list_id,block_common_exploits,certificate_id,ssl_forced,http2_support,hsts_enabled,hsts_subdomains,caching_enabled,trust_forwarded_proto,advanced_config,custom_locations_json,created_at,updated_at FROM hosts WHERE id=?`, id)
	return scanHost(row)
}

type rowScanner interface{ Scan(...any) error }

func scanHost(row rowScanner) (model.Host, error) {
	var h model.Host
	var domainsJSON, locationsJSON, createdRaw, updatedRaw string
	var enabled, websockets, preserve, stats, storeQuery, exploits, sslForced, http2, hsts, hstsSubs, caching, trustProto int
	var provider, accessList, certificate sql.NullInt64
	if err := row.Scan(&h.ID, &h.Name, &domainsJSON, &h.Scheme, &h.ForwardHost, &h.ForwardPort, &enabled, &websockets, &preserve, &stats, &storeQuery, &provider, &accessList, &exploits, &certificate, &sslForced, &http2, &hsts, &hstsSubs, &caching, &trustProto, &h.AdvancedConfig, &locationsJSON, &createdRaw, &updatedRaw); err != nil {
		return h, err
	}
	_ = json.Unmarshal([]byte(domainsJSON), &h.Domains)
	_ = json.Unmarshal([]byte(locationsJSON), &h.CustomLocations)
	if h.Domains == nil {
		h.Domains = []string{}
	}
	if h.CustomLocations == nil {
		h.CustomLocations = []model.CustomLocation{}
	}
	h.Enabled = enabled != 0
	h.WebSockets = websockets != 0
	h.PreserveHost = preserve != 0
	h.StatisticsEnabled = stats != 0
	h.StoreQueryString = storeQuery != 0
	h.BlockCommonExploits = exploits != 0
	h.SSLForced = sslForced != 0
	h.HTTP2Support = http2 != 0
	h.HSTSEnabled = hsts != 0
	h.HSTSSubdomains = hstsSubs != 0
	h.CachingEnabled = caching != 0
	h.TrustForwardedProto = trustProto != 0
	if provider.Valid {
		v := provider.Int64
		h.TrustedProxyProviderID = &v
	}
	if accessList.Valid {
		v := accessList.Int64
		h.AccessListID = &v
	}
	if certificate.Valid {
		v := certificate.Int64
		h.CertificateID = &v
	}
	h.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdRaw)
	h.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedRaw)
	return h, nil
}

func (s *Store) CreateHost(in model.HostInput) (model.Host, error) {
	domains, _ := json.Marshal(in.Domains)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.Exec(`INSERT INTO hosts(name,domains_json,scheme,forward_host,forward_port,enabled,websockets,preserve_host,statistics_enabled,store_query_string,trusted_proxy_provider_id,access_list_id,block_common_exploits,certificate_id,ssl_forced,http2_support,hsts_enabled,hsts_subdomains,caching_enabled,trust_forwarded_proto,advanced_config,custom_locations_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		in.Name, string(domains), in.Scheme, in.ForwardHost, in.ForwardPort, btoi(in.Enabled), btoi(in.WebSockets), btoi(in.PreserveHost), btoi(in.StatisticsEnabled), btoi(in.StoreQueryString), nullableInt(in.TrustedProxyProviderID), nullableInt(in.AccessListID), btoi(in.BlockCommonExploits), nullableInt(in.CertificateID), btoi(in.SSLForced), btoi(in.HTTP2Support), btoi(in.HSTSEnabled), btoi(in.HSTSSubdomains), btoi(in.CachingEnabled), btoi(in.TrustForwardedProto), in.AdvancedConfig, locationsJSON(in.CustomLocations), now, now)
	if err != nil {
		return model.Host{}, err
	}
	id, _ := res.LastInsertId()
	return s.GetHost(id)
}

// CreateHosts inserts a migration batch in one database transaction. Proxy activation
// is intentionally performed by the control plane after this transaction commits.
func (s *Store) CreateHosts(inputs []model.HostInput) ([]int64, error) {
	if len(inputs) == 0 {
		return []int64{}, nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339Nano)
	ids := make([]int64, 0, len(inputs))
	for _, in := range inputs {
		domains, _ := json.Marshal(in.Domains)
		res, err := tx.Exec(`INSERT INTO hosts(name,domains_json,scheme,forward_host,forward_port,enabled,websockets,preserve_host,statistics_enabled,store_query_string,trusted_proxy_provider_id,access_list_id,block_common_exploits,certificate_id,ssl_forced,http2_support,hsts_enabled,hsts_subdomains,caching_enabled,trust_forwarded_proto,advanced_config,custom_locations_json,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			in.Name, string(domains), in.Scheme, in.ForwardHost, in.ForwardPort, btoi(in.Enabled), btoi(in.WebSockets), btoi(in.PreserveHost), btoi(in.StatisticsEnabled), btoi(in.StoreQueryString), nullableInt(in.TrustedProxyProviderID), nullableInt(in.AccessListID), btoi(in.BlockCommonExploits), nullableInt(in.CertificateID), btoi(in.SSLForced), btoi(in.HTTP2Support), btoi(in.HSTSEnabled), btoi(in.HSTSSubdomains), btoi(in.CachingEnabled), btoi(in.TrustForwardedProto), in.AdvancedConfig, locationsJSON(in.CustomLocations), now, now)
		if err != nil {
			return nil, err
		}
		id, err := res.LastInsertId()
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return ids, nil
}

func (s *Store) DeleteHosts(ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, id := range ids {
		if _, err := tx.Exec(`DELETE FROM hosts WHERE id=?`, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) UpdateHost(id int64, in model.HostInput) (model.Host, error) {
	domains, _ := json.Marshal(in.Domains)
	res, err := s.db.Exec(`UPDATE hosts SET name=?,domains_json=?,scheme=?,forward_host=?,forward_port=?,enabled=?,websockets=?,preserve_host=?,statistics_enabled=?,store_query_string=?,trusted_proxy_provider_id=?,access_list_id=?,block_common_exploits=?,certificate_id=?,ssl_forced=?,http2_support=?,hsts_enabled=?,hsts_subdomains=?,caching_enabled=?,trust_forwarded_proto=?,advanced_config=?,custom_locations_json=?,updated_at=? WHERE id=?`,
		in.Name, string(domains), in.Scheme, in.ForwardHost, in.ForwardPort, btoi(in.Enabled), btoi(in.WebSockets), btoi(in.PreserveHost), btoi(in.StatisticsEnabled), btoi(in.StoreQueryString), nullableInt(in.TrustedProxyProviderID), nullableInt(in.AccessListID), btoi(in.BlockCommonExploits), nullableInt(in.CertificateID), btoi(in.SSLForced), btoi(in.HTTP2Support), btoi(in.HSTSEnabled), btoi(in.HSTSSubdomains), btoi(in.CachingEnabled), btoi(in.TrustForwardedProto), in.AdvancedConfig, locationsJSON(in.CustomLocations), time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return model.Host{}, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return model.Host{}, sql.ErrNoRows
	}
	return s.GetHost(id)
}

func (s *Store) DeleteHost(id int64) error {
	res, err := s.db.Exec(`DELETE FROM hosts WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func locationsJSON(v []model.CustomLocation) string {
	if v == nil {
		v = []model.CustomLocation{}
	}
	raw, _ := json.Marshal(v)
	return string(raw)
}

func (s *Store) ListAccessLists() ([]model.AccessList, error) {
	rows, err := s.db.Query(`SELECT id,name,satisfy_any,pass_auth,auth_enabled,rules_json,auth_file,created_at,updated_at FROM access_lists ORDER BY name COLLATE NOCASE,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.AccessList{}
	for rows.Next() {
		v, err := scanAccessList(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) GetAccessList(id int64) (model.AccessList, error) {
	return scanAccessList(s.db.QueryRow(`SELECT id,name,satisfy_any,pass_auth,auth_enabled,rules_json,auth_file,created_at,updated_at FROM access_lists WHERE id=?`, id))
}

func scanAccessList(row rowScanner) (model.AccessList, error) {
	var v model.AccessList
	var satisfy, pass, authEnabled int
	var rules, created, updated string
	if err := row.Scan(&v.ID, &v.Name, &satisfy, &pass, &authEnabled, &rules, &v.AuthFile, &created, &updated); err != nil {
		return v, err
	}
	v.SatisfyAny, v.PassAuth, v.AuthEnabled = satisfy != 0, pass != 0, authEnabled != 0
	_ = json.Unmarshal([]byte(rules), &v.Rules)
	if v.Rules == nil {
		v.Rules = []model.AccessRule{}
	}
	v.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	v.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return v, nil
}

func (s *Store) CreateAccessList(in model.AccessListInput) (model.AccessList, error) {
	raw, _ := json.Marshal(in.Rules)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.Exec(`INSERT INTO access_lists(name,satisfy_any,pass_auth,auth_enabled,rules_json,auth_file,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)`, in.Name, btoi(in.SatisfyAny), btoi(in.PassAuth), btoi(in.AuthEnabled), string(raw), in.AuthFile, now, now)
	if err != nil {
		return model.AccessList{}, err
	}
	id, _ := res.LastInsertId()
	return s.GetAccessList(id)
}

func (s *Store) UpdateAccessList(id int64, in model.AccessListInput) (model.AccessList, error) {
	raw, _ := json.Marshal(in.Rules)
	res, err := s.db.Exec(`UPDATE access_lists SET name=?,satisfy_any=?,pass_auth=?,auth_enabled=?,rules_json=?,auth_file=?,updated_at=? WHERE id=?`, in.Name, btoi(in.SatisfyAny), btoi(in.PassAuth), btoi(in.AuthEnabled), string(raw), in.AuthFile, time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return model.AccessList{}, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return model.AccessList{}, sql.ErrNoRows
	}
	return s.GetAccessList(id)
}

func (s *Store) DeleteAccessList(id int64) error {
	_, err := s.db.Exec(`DELETE FROM access_lists WHERE id=?`, id)
	return err
}

func (s *Store) ListRedirectHosts() ([]model.RedirectHost, error) {
	rows, err := s.db.Query(`SELECT id,domains_json,forward_http_code,forward_scheme,forward_domain_name,preserve_path,certificate_id,ssl_forced,http2_support,hsts_enabled,hsts_subdomains,block_exploits,advanced_config,enabled,created_at,updated_at FROM redirect_hosts ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.RedirectHost{}
	for rows.Next() {
		v, err := scanRedirectHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func scanRedirectHost(row rowScanner) (model.RedirectHost, error) {
	var v model.RedirectHost
	var domains, created, updated string
	var preserve, ssl, http2, hsts, subs, exploits, enabled int
	var cert sql.NullInt64
	if err := row.Scan(&v.ID, &domains, &v.ForwardHTTPCode, &v.ForwardScheme, &v.ForwardDomainName, &preserve, &cert, &ssl, &http2, &hsts, &subs, &exploits, &v.AdvancedConfig, &enabled, &created, &updated); err != nil {
		return v, err
	}
	_ = json.Unmarshal([]byte(domains), &v.Domains)
	if v.Domains == nil {
		v.Domains = []string{}
	}
	v.PreservePath = preserve != 0
	v.SSLForced = ssl != 0
	v.HTTP2Support = http2 != 0
	v.HSTSEnabled = hsts != 0
	v.HSTSSubdomains = subs != 0
	v.BlockExploits = exploits != 0
	v.Enabled = enabled != 0
	if cert.Valid {
		x := cert.Int64
		v.CertificateID = &x
	}
	v.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	v.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return v, nil
}
func (s *Store) CreateRedirectHost(in model.RedirectHostInput) (model.RedirectHost, error) {
	raw, _ := json.Marshal(in.Domains)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.Exec(`INSERT INTO redirect_hosts(domains_json,forward_http_code,forward_scheme,forward_domain_name,preserve_path,certificate_id,ssl_forced,http2_support,hsts_enabled,hsts_subdomains,block_exploits,advanced_config,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, string(raw), in.ForwardHTTPCode, in.ForwardScheme, in.ForwardDomainName, btoi(in.PreservePath), nullableInt(in.CertificateID), btoi(in.SSLForced), btoi(in.HTTP2Support), btoi(in.HSTSEnabled), btoi(in.HSTSSubdomains), btoi(in.BlockExploits), in.AdvancedConfig, btoi(in.Enabled), now, now)
	if err != nil {
		return model.RedirectHost{}, err
	}
	id, _ := res.LastInsertId()
	return scanRedirectHost(s.db.QueryRow(`SELECT id,domains_json,forward_http_code,forward_scheme,forward_domain_name,preserve_path,certificate_id,ssl_forced,http2_support,hsts_enabled,hsts_subdomains,block_exploits,advanced_config,enabled,created_at,updated_at FROM redirect_hosts WHERE id=?`, id))
}
func (s *Store) GetRedirectHost(id int64) (model.RedirectHost, error) {
	return scanRedirectHost(s.db.QueryRow(`SELECT id,domains_json,forward_http_code,forward_scheme,forward_domain_name,preserve_path,certificate_id,ssl_forced,http2_support,hsts_enabled,hsts_subdomains,block_exploits,advanced_config,enabled,created_at,updated_at FROM redirect_hosts WHERE id=?`, id))
}
func (s *Store) UpdateRedirectHost(id int64, in model.RedirectHostInput) (model.RedirectHost, error) {
	raw, _ := json.Marshal(in.Domains)
	res, err := s.db.Exec(`UPDATE redirect_hosts SET domains_json=?,forward_http_code=?,forward_scheme=?,forward_domain_name=?,preserve_path=?,certificate_id=?,ssl_forced=?,http2_support=?,hsts_enabled=?,hsts_subdomains=?,block_exploits=?,advanced_config=?,enabled=?,updated_at=? WHERE id=?`, string(raw), in.ForwardHTTPCode, in.ForwardScheme, in.ForwardDomainName, btoi(in.PreservePath), nullableInt(in.CertificateID), btoi(in.SSLForced), btoi(in.HTTP2Support), btoi(in.HSTSEnabled), btoi(in.HSTSSubdomains), btoi(in.BlockExploits), in.AdvancedConfig, btoi(in.Enabled), time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return model.RedirectHost{}, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return model.RedirectHost{}, sql.ErrNoRows
	}
	return s.GetRedirectHost(id)
}
func (s *Store) DeleteRedirectHost(id int64) error {
	_, err := s.db.Exec(`DELETE FROM redirect_hosts WHERE id=?`, id)
	return err
}

func (s *Store) ListDeadHosts() ([]model.DeadHost, error) {
	rows, err := s.db.Query(`SELECT id,domains_json,certificate_id,ssl_forced,http2_support,hsts_enabled,hsts_subdomains,advanced_config,enabled,created_at,updated_at FROM dead_hosts ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.DeadHost{}
	for rows.Next() {
		v, err := scanDeadHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func scanDeadHost(row rowScanner) (model.DeadHost, error) {
	var v model.DeadHost
	var domains, created, updated string
	var ssl, http2, hsts, subs, enabled int
	var cert sql.NullInt64
	if err := row.Scan(&v.ID, &domains, &cert, &ssl, &http2, &hsts, &subs, &v.AdvancedConfig, &enabled, &created, &updated); err != nil {
		return v, err
	}
	_ = json.Unmarshal([]byte(domains), &v.Domains)
	if v.Domains == nil {
		v.Domains = []string{}
	}
	if cert.Valid {
		x := cert.Int64
		v.CertificateID = &x
	}
	v.SSLForced = ssl != 0
	v.HTTP2Support = http2 != 0
	v.HSTSEnabled = hsts != 0
	v.HSTSSubdomains = subs != 0
	v.Enabled = enabled != 0
	v.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	v.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return v, nil
}
func (s *Store) CreateDeadHost(in model.DeadHostInput) (model.DeadHost, error) {
	raw, _ := json.Marshal(in.Domains)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.Exec(`INSERT INTO dead_hosts(domains_json,certificate_id,ssl_forced,http2_support,hsts_enabled,hsts_subdomains,advanced_config,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, string(raw), nullableInt(in.CertificateID), btoi(in.SSLForced), btoi(in.HTTP2Support), btoi(in.HSTSEnabled), btoi(in.HSTSSubdomains), in.AdvancedConfig, btoi(in.Enabled), now, now)
	if err != nil {
		return model.DeadHost{}, err
	}
	id, _ := res.LastInsertId()
	return scanDeadHost(s.db.QueryRow(`SELECT id,domains_json,certificate_id,ssl_forced,http2_support,hsts_enabled,hsts_subdomains,advanced_config,enabled,created_at,updated_at FROM dead_hosts WHERE id=?`, id))
}
func (s *Store) GetDeadHost(id int64) (model.DeadHost, error) {
	return scanDeadHost(s.db.QueryRow(`SELECT id,domains_json,certificate_id,ssl_forced,http2_support,hsts_enabled,hsts_subdomains,advanced_config,enabled,created_at,updated_at FROM dead_hosts WHERE id=?`, id))
}
func (s *Store) UpdateDeadHost(id int64, in model.DeadHostInput) (model.DeadHost, error) {
	raw, _ := json.Marshal(in.Domains)
	res, err := s.db.Exec(`UPDATE dead_hosts SET domains_json=?,certificate_id=?,ssl_forced=?,http2_support=?,hsts_enabled=?,hsts_subdomains=?,advanced_config=?,enabled=?,updated_at=? WHERE id=?`, string(raw), nullableInt(in.CertificateID), btoi(in.SSLForced), btoi(in.HTTP2Support), btoi(in.HSTSEnabled), btoi(in.HSTSSubdomains), in.AdvancedConfig, btoi(in.Enabled), time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return model.DeadHost{}, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return model.DeadHost{}, sql.ErrNoRows
	}
	return s.GetDeadHost(id)
}
func (s *Store) DeleteDeadHost(id int64) error {
	_, err := s.db.Exec(`DELETE FROM dead_hosts WHERE id=?`, id)
	return err
}

func (s *Store) ListStreams() ([]model.Stream, error) {
	rows, err := s.db.Query(`SELECT id,incoming_port,forward_host,forward_port,tcp_forwarding,udp_forwarding,certificate_id,enabled,created_at,updated_at FROM streams ORDER BY incoming_port,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Stream{}
	for rows.Next() {
		v, err := scanStream(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func scanStream(row rowScanner) (model.Stream, error) {
	var v model.Stream
	var tcp, udp, enabled int
	var cert sql.NullInt64
	var created, updated string
	if err := row.Scan(&v.ID, &v.IncomingPort, &v.ForwardHost, &v.ForwardPort, &tcp, &udp, &cert, &enabled, &created, &updated); err != nil {
		return v, err
	}
	v.TCPForwarding = tcp != 0
	v.UDPForwarding = udp != 0
	v.Enabled = enabled != 0
	if cert.Valid {
		x := cert.Int64
		v.CertificateID = &x
	}
	v.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	v.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return v, nil
}
func (s *Store) CreateStream(in model.StreamInput) (model.Stream, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := s.db.Exec(`INSERT INTO streams(incoming_port,forward_host,forward_port,tcp_forwarding,udp_forwarding,certificate_id,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, in.IncomingPort, in.ForwardHost, in.ForwardPort, btoi(in.TCPForwarding), btoi(in.UDPForwarding), nullableInt(in.CertificateID), btoi(in.Enabled), now, now)
	if err != nil {
		return model.Stream{}, err
	}
	id, _ := res.LastInsertId()
	return scanStream(s.db.QueryRow(`SELECT id,incoming_port,forward_host,forward_port,tcp_forwarding,udp_forwarding,certificate_id,enabled,created_at,updated_at FROM streams WHERE id=?`, id))
}
func (s *Store) GetStream(id int64) (model.Stream, error) {
	return scanStream(s.db.QueryRow(`SELECT id,incoming_port,forward_host,forward_port,tcp_forwarding,udp_forwarding,certificate_id,enabled,created_at,updated_at FROM streams WHERE id=?`, id))
}
func (s *Store) UpdateStream(id int64, in model.StreamInput) (model.Stream, error) {
	res, err := s.db.Exec(`UPDATE streams SET incoming_port=?,forward_host=?,forward_port=?,tcp_forwarding=?,udp_forwarding=?,certificate_id=?,enabled=?,updated_at=? WHERE id=?`, in.IncomingPort, in.ForwardHost, in.ForwardPort, btoi(in.TCPForwarding), btoi(in.UDPForwarding), nullableInt(in.CertificateID), btoi(in.Enabled), time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return model.Stream{}, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return model.Stream{}, sql.ErrNoRows
	}
	return s.GetStream(id)
}
func (s *Store) DeleteStream(id int64) error {
	_, err := s.db.Exec(`DELETE FROM streams WHERE id=?`, id)
	return err
}

func (s *Store) ListCertificates() ([]model.Certificate, error) {
	rows, err := s.db.Query(`SELECT id,name,description,provider,domains_json,challenge,email,dns_provider,auto_renew,cert_path,key_path,expires_at,last_renewed,last_error,created_at,updated_at FROM certificates ORDER BY name COLLATE NOCASE,id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Certificate{}
	for rows.Next() {
		c, err := scanCertificate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
func (s *Store) GetCertificate(id int64) (model.Certificate, error) {
	return scanCertificate(s.db.QueryRow(`SELECT id,name,description,provider,domains_json,challenge,email,dns_provider,auto_renew,cert_path,key_path,expires_at,last_renewed,last_error,created_at,updated_at FROM certificates WHERE id=?`, id))
}
func scanCertificate(row rowScanner) (model.Certificate, error) {
	var c model.Certificate
	var domainsJSON, createdRaw, updatedRaw string
	var auto int
	var expires, renewed sql.NullString
	if err := row.Scan(&c.ID, &c.Name, &c.Description, &c.Provider, &domainsJSON, &c.Challenge, &c.Email, &c.DNSProvider, &auto, &c.CertPath, &c.KeyPath, &expires, &renewed, &c.LastError, &createdRaw, &updatedRaw); err != nil {
		return c, err
	}
	_ = json.Unmarshal([]byte(domainsJSON), &c.Domains)
	if c.Domains == nil {
		c.Domains = []string{}
	}
	c.AutoRenew = auto != 0
	if expires.Valid {
		if t, e := time.Parse(time.RFC3339Nano, expires.String); e == nil {
			c.ExpiresAt = &t
		}
	}
	if renewed.Valid {
		if t, e := time.Parse(time.RFC3339Nano, renewed.String); e == nil {
			c.LastRenewed = &t
		}
	}
	c.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdRaw)
	c.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedRaw)
	return c, nil
}
func (s *Store) CreateCertificate(c model.Certificate) (model.Certificate, error) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	raw, _ := json.Marshal(c.Domains)
	res, err := s.db.Exec(`INSERT INTO certificates(name,description,provider,domains_json,challenge,email,dns_provider,auto_renew,cert_path,key_path,expires_at,last_renewed,last_error,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, c.Name, c.Description, c.Provider, string(raw), c.Challenge, c.Email, c.DNSProvider, btoi(c.AutoRenew), c.CertPath, c.KeyPath, nullableTime(c.ExpiresAt), nullableTime(c.LastRenewed), c.LastError, now, now)
	if err != nil {
		return model.Certificate{}, err
	}
	id, _ := res.LastInsertId()
	return s.GetCertificate(id)
}
func (s *Store) UpdateCertificate(c model.Certificate) (model.Certificate, error) {
	raw, _ := json.Marshal(c.Domains)
	res, err := s.db.Exec(`UPDATE certificates SET name=?,description=?,provider=?,domains_json=?,challenge=?,email=?,dns_provider=?,auto_renew=?,cert_path=?,key_path=?,expires_at=?,last_renewed=?,last_error=?,updated_at=? WHERE id=?`, c.Name, c.Description, c.Provider, string(raw), c.Challenge, c.Email, c.DNSProvider, btoi(c.AutoRenew), c.CertPath, c.KeyPath, nullableTime(c.ExpiresAt), nullableTime(c.LastRenewed), c.LastError, time.Now().UTC().Format(time.RFC3339Nano), c.ID)
	if err != nil {
		return model.Certificate{}, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return model.Certificate{}, sql.ErrNoRows
	}
	return s.GetCertificate(c.ID)
}
func (s *Store) DeleteCertificate(id int64) error {
	res, err := s.db.Exec(`DELETE FROM certificates WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}
func nullableTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func (s *Store) ListProviders() ([]model.TrustedProxyProvider, error) {
	rows, err := s.db.Query(`SELECT id,slug,name,kind,real_ip_header,auto_update,source_ipv4,source_ipv6,cidrs_json,last_checked,last_changed,last_error FROM trusted_proxy_providers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.TrustedProxyProvider{}
	for rows.Next() {
		p, err := scanProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetProvider(id int64) (model.TrustedProxyProvider, error) {
	return scanProvider(s.db.QueryRow(`SELECT id,slug,name,kind,real_ip_header,auto_update,source_ipv4,source_ipv6,cidrs_json,last_checked,last_changed,last_error FROM trusted_proxy_providers WHERE id=?`, id))
}

func (s *Store) CreateProvider(slug string, in model.TrustedProxyProviderInput) (model.TrustedProxyProvider, error) {
	cidrs, _ := json.Marshal(in.CIDRs)
	res, err := s.db.Exec(`INSERT INTO trusted_proxy_providers(slug,name,kind,real_ip_header,auto_update,source_ipv4,source_ipv6,cidrs_json,last_error) VALUES(?,?,?,?,0,'','',?,'')`, slug, in.Name, "manual", in.Header, string(cidrs))
	if err != nil {
		return model.TrustedProxyProvider{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return model.TrustedProxyProvider{}, err
	}
	return s.GetProvider(id)
}

func (s *Store) UpdateProvider(id int64, in model.TrustedProxyProviderInput) (model.TrustedProxyProvider, error) {
	cidrs, _ := json.Marshal(in.CIDRs)
	res, err := s.db.Exec(`UPDATE trusted_proxy_providers SET name=?,real_ip_header=?,cidrs_json=?,last_error='' WHERE id=? AND kind='manual'`, in.Name, in.Header, string(cidrs), id)
	if err != nil {
		return model.TrustedProxyProvider{}, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return model.TrustedProxyProvider{}, sql.ErrNoRows
	}
	return s.GetProvider(id)
}

func (s *Store) DeleteProvider(id int64) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var kind string
	if err := tx.QueryRow(`SELECT kind FROM trusted_proxy_providers WHERE id=?`, id).Scan(&kind); err != nil {
		return 0, err
	}
	if kind != "manual" {
		return 0, fmt.Errorf("built-in provider cannot be deleted")
	}
	var affected int64
	if err := tx.QueryRow(`SELECT COUNT(*) FROM hosts WHERE trusted_proxy_provider_id=?`, id).Scan(&affected); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`DELETE FROM trusted_proxy_providers WHERE id=?`, id); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return affected, nil
}

func scanProvider(row rowScanner) (model.TrustedProxyProvider, error) {
	var p model.TrustedProxyProvider
	var auto int
	var cidrs string
	var checked, changed sql.NullString
	if err := row.Scan(&p.ID, &p.Slug, &p.Name, &p.Kind, &p.Header, &auto, &p.SourceIPv4, &p.SourceIPv6, &cidrs, &checked, &changed, &p.LastError); err != nil {
		return p, err
	}
	p.AutoUpdate = auto != 0
	_ = json.Unmarshal([]byte(cidrs), &p.CIDRs)
	if p.CIDRs == nil {
		p.CIDRs = []string{}
	}
	if checked.Valid {
		if t, e := time.Parse(time.RFC3339Nano, checked.String); e == nil {
			p.LastChecked = &t
		}
	}
	if changed.Valid {
		if t, e := time.Parse(time.RFC3339Nano, changed.String); e == nil {
			p.LastChanged = &t
		}
	}
	return p, nil
}

func (s *Store) UpdateProviderResult(id int64, cidrs []string, checked time.Time, changed bool, lastErr string) error {
	data, _ := json.Marshal(cidrs)
	if changed {
		_, err := s.db.Exec(`UPDATE trusted_proxy_providers SET cidrs_json=?,last_checked=?,last_changed=?,last_error=? WHERE id=?`, string(data), checked.Format(time.RFC3339Nano), checked.Format(time.RFC3339Nano), lastErr, id)
		return err
	}
	_, err := s.db.Exec(`UPDATE trusted_proxy_providers SET last_checked=?,last_error=? WHERE id=?`, checked.Format(time.RFC3339Nano), lastErr, id)
	return err
}

func (s *Store) GetZentLoop() (model.ZentLoopConfig, error) {
	var raw string
	if err := s.db.QueryRow(`SELECT config_json FROM integration_settings WHERE slug='zentloop'`).Scan(&raw); err != nil {
		return model.ZentLoopConfig{}, err
	}
	var cfg model.ZentLoopConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return cfg, err
	}
	for i := range cfg.Rules {
		if cfg.Rules[i].Action != "block" {
			cfg.Rules[i].Action = "zentloop"
		}
	}
	if cfg.Fallback != "503" {
		cfg.Fallback = "block"
	}
	return cfg, nil
}

func (s *Store) SetZentLoop(cfg model.ZentLoopConfig) error {
	raw, _ := json.Marshal(cfg)
	_, err := s.db.Exec(`INSERT INTO integration_settings(slug,config_json,updated_at) VALUES('zentloop',?,?) ON CONFLICT(slug) DO UPDATE SET config_json=excluded.config_json,updated_at=excluded.updated_at`, string(raw), time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) CreateAPIKey(name string, scopes []string) (model.APIKey, string, error) {
	token, err := auth.RandomToken(32)
	if err != nil {
		return model.APIKey{}, "", err
	}
	prefix := token
	if len(prefix) > 10 {
		prefix = prefix[:10]
	}
	raw, _ := json.Marshal(scopes)
	now := time.Now().UTC()
	res, err := s.db.Exec(`INSERT INTO api_keys(name,prefix,token_hash,scopes_json,created_at) VALUES(?,?,?,?,?)`, name, prefix, auth.TokenHash(token), string(raw), now.Format(time.RFC3339Nano))
	if err != nil {
		return model.APIKey{}, "", err
	}
	id, _ := res.LastInsertId()
	return model.APIKey{ID: id, Name: name, Prefix: prefix, Scopes: scopes, CreatedAt: now}, token, nil
}

func (s *Store) ValidateAPIKey(token string) (keyID int64, name string, scopes []string, ok bool, err error) {
	var raw string
	var revoked sql.NullString
	err = s.db.QueryRow(`SELECT id,name,scopes_json,revoked_at FROM api_keys WHERE token_hash=?`, auth.TokenHash(token)).Scan(&keyID, &name, &raw, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", nil, false, nil
	}
	if err != nil {
		return 0, "", nil, false, err
	}
	if revoked.Valid {
		return 0, "", nil, false, nil
	}
	_ = json.Unmarshal([]byte(raw), &scopes)
	_, _ = s.db.Exec(`UPDATE api_keys SET last_used=? WHERE id=?`, time.Now().UTC().Format(time.RFC3339Nano), keyID)
	return keyID, name, scopes, true, nil
}

func (s *Store) ListAPIKeys() ([]model.APIKey, error) {
	rows, err := s.db.Query(`SELECT id,name,prefix,scopes_json,created_at,last_used,revoked_at FROM api_keys ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.APIKey{}
	for rows.Next() {
		var k model.APIKey
		var raw, created string
		var last, rev sql.NullString
		if err := rows.Scan(&k.ID, &k.Name, &k.Prefix, &raw, &created, &last, &rev); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(raw), &k.Scopes)
		if k.Scopes == nil {
			k.Scopes = []string{}
		}
		k.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		if last.Valid {
			if t, e := time.Parse(time.RFC3339Nano, last.String); e == nil {
				k.LastUsed = &t
			}
		}
		if rev.Valid {
			if t, e := time.Parse(time.RFC3339Nano, rev.String); e == nil {
				k.RevokedAt = &t
			}
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) RevokeAPIKey(id int64) error {
	res, err := s.db.Exec(`UPDATE api_keys SET revoked_at=? WHERE id=? AND revoked_at IS NULL`, time.Now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func rawRequestArgs(r model.RawRequest) []any {
	var upstream any
	if r.UpstreamTimeMS != nil {
		upstream = *r.UpstreamTimeMS
	}
	return []any{r.At.UTC().Format(time.RFC3339Nano), r.Host, r.IP, r.Method, r.Path, r.Query, r.Status, r.Bytes, r.RequestTimeMS, upstream, r.UserAgent, r.Referer, r.HTTPVersion, r.TLSVersion, r.ZentLoop}
}

func (s *Store) InsertRawRequest(r model.RawRequest) error {
	_, err := s.db.Exec(`INSERT INTO raw_requests(at,host,ip,method,path,query,status,bytes,request_time_ms,upstream_time_ms,user_agent,referer,http_version,tls_version,zentloop) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, rawRequestArgs(r)...)
	return err
}

func (s *Store) AnalyticsOffset(name string) (int64, error) {
	var offset int64
	err := s.db.QueryRow(`SELECT offset FROM analytics_state WHERE name=?`, name).Scan(&offset)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return offset, err
}

func (s *Store) SetAnalyticsOffset(name string, offset int64) error {
	_, err := s.db.Exec(`INSERT INTO analytics_state(name,offset,updated_at) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET offset=excluded.offset,updated_at=excluded.updated_at`, name, offset, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) InsertRawRequestWithOffset(name string, offset int64, r model.RawRequest) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO raw_requests(at,host,ip,method,path,query,status,bytes,request_time_ms,upstream_time_ms,user_agent,referer,http_version,tls_version,zentloop) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, rawRequestArgs(r)...); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO analytics_state(name,offset,updated_at) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET offset=excluded.offset,updated_at=excluded.updated_at`, name, offset, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) CleanupRawRequests(retentionDays int) error {
	cut := time.Now().UTC().Add(-time.Duration(retentionDays) * 24 * time.Hour).Format(time.RFC3339Nano)
	_, err := s.db.Exec(`DELETE FROM raw_requests WHERE at < ?`, cut)
	return err
}

func (s *Store) RecentRequests(since time.Time, host, zentloop string, limit int) ([]model.RawRequest, error) {
	if limit < 1 || limit > 1000 {
		limit = 200
	}
	query := `SELECT id,at,host,ip,method,path,query,status,bytes,request_time_ms,upstream_time_ms,user_agent,referer,http_version,tls_version,zentloop FROM raw_requests WHERE at>=?`
	args := []any{since.UTC().Format(time.RFC3339Nano)}
	if host != "" {
		query += " AND host=?"
		args = append(args, host)
	}
	if zentloop == "only" {
		query += " AND zentloop=1"
	} else if zentloop == "without" {
		query += " AND zentloop=0"
	}
	query += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.RawRequest{}
	for rows.Next() {
		var r model.RawRequest
		var at string
		var up sql.NullFloat64
		if err := rows.Scan(&r.ID, &at, &r.Host, &r.IP, &r.Method, &r.Path, &r.Query, &r.Status, &r.Bytes, &r.RequestTimeMS, &up, &r.UserAgent, &r.Referer, &r.HTTPVersion, &r.TLSVersion, &r.ZentLoop); err != nil {
			return nil, err
		}
		r.At, _ = time.Parse(time.RFC3339Nano, at)
		if up.Valid {
			v := up.Float64
			r.UpstreamTimeMS = &v
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) StatsSummary(since time.Time, host, zentloop string) (model.StatsSummary, error) {
	out := model.StatsSummary{Since: since.UTC(), StatusClasses: map[string]int64{"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}, TopHosts: []model.CountItem{}, TopPaths: []model.CountItem{}, TopIPs: []model.CountItem{}}
	where := "at>=?"
	args := []any{since.UTC().Format(time.RFC3339Nano)}
	if host != "" {
		where += " AND host=?"
		args = append(args, host)
	}
	if zentloop == "only" {
		where += " AND zentloop=1"
	} else if zentloop == "without" {
		where += " AND zentloop=0"
	}
	q := `SELECT COUNT(*),COUNT(DISTINCT ip),COALESCE(SUM(bytes),0),COALESCE(SUM(CASE WHEN status>=400 THEN 1 ELSE 0 END),0),COALESCE(AVG(request_time_ms),0),
	COALESCE(SUM(CASE WHEN status BETWEEN 200 AND 299 THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN status BETWEEN 300 AND 399 THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN status BETWEEN 400 AND 499 THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN status>=500 THEN 1 ELSE 0 END),0) FROM raw_requests WHERE ` + where
	var c2, c3, c4, c5 int64
	if err := s.db.QueryRow(q, args...).Scan(&out.Requests, &out.UniqueIPs, &out.Bytes, &out.Errors, &out.AverageTimeMS, &c2, &c3, &c4, &c5); err != nil {
		return out, err
	}
	out.StatusClasses["2xx"] = c2
	out.StatusClasses["3xx"] = c3
	out.StatusClasses["4xx"] = c4
	out.StatusClasses["5xx"] = c5
	var err error
	out.TopHosts, err = s.topCounts("host", where, args, 8)
	if err != nil {
		return out, err
	}
	out.TopPaths, err = s.topCounts("path", where, args, 8)
	if err != nil {
		return out, err
	}
	out.TopIPs, err = s.topCounts("ip", where, args, 8)
	if err != nil {
		return out, err
	}
	return out, nil
}

func (s *Store) topCounts(column, where string, args []any, limit int) ([]model.CountItem, error) {
	allowed := map[string]bool{"host": true, "path": true, "ip": true}
	if !allowed[column] {
		return nil, fmt.Errorf("invalid column")
	}
	if column == "ip" {
		where = "(" + where + ") AND ip <> ''"
	}
	q := `SELECT ` + column + `,COUNT(*) AS c FROM raw_requests WHERE ` + where + ` GROUP BY ` + column + ` ORDER BY c DESC LIMIT ?`
	a := append(append([]any{}, args...), limit)
	rows, err := s.db.Query(q, a...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.CountItem{}
	for rows.Next() {
		var i model.CountItem
		if err := rows.Scan(&i.Key, &i.Count); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

func (s *Store) AddAudit(actor, action, objectType, objectID, detail string) {
	_, _ = s.db.Exec(`INSERT INTO audit_log(at,actor,action,object_type,object_id,detail) VALUES(?,?,?,?,?,?)`, time.Now().UTC().Format(time.RFC3339Nano), actor, action, objectType, objectID, detail)
}

func (s *Store) Audit(limit int) ([]map[string]any, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT id,at,actor,action,object_type,object_id,detail FROM audit_log ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var at, actorN, action, objType, objID, detail string
		if err := rows.Scan(&id, &at, &actorN, &action, &objType, &objID, &detail); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"id": id, "at": at, "actor": actorN, "action": action, "object_type": objType, "object_id": objID, "detail": detail})
	}
	return out, rows.Err()
}

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func nullableInt(v *int64) any {
	if v == nil {
		return nil
	}
	return *v
}
func btoi(v bool) int {
	if v {
		return 1
	}
	return 0
}
