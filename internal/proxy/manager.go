package proxy

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/zentproxy/zentproxy/internal/db"
	"github.com/zentproxy/zentproxy/internal/model"
)

type Manager struct {
	store                *db.Store
	dataDir              string
	trustedTransportHops []string
	mu                   sync.Mutex
}

func NewManager(store *db.Store, dataDir string) *Manager {
	return &Manager{store: store, dataDir: dataDir, trustedTransportHops: detectTrustedTransportHops()}
}

func detectTrustedTransportHops() []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if ip := net.ParseIP(value); ip != nil {
			if ip.To4() != nil {
				value = ip.String() + "/32"
			} else {
				value = ip.String() + "/128"
			}
		} else if _, _, err := net.ParseCIDR(value); err != nil {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}

	// Docker and other container runtimes can hide the original TCP peer behind
	// a local gateway before OpenResty sees the connection. Trust only exact
	// transport-hop addresses, never an entire RFC1918 range. Docker Desktop
	// commonly presents published-port traffic as 192.168.65.1 even when that
	// address is not the container's default route.
	add("192.168.65.1")
	if raw, err := os.ReadFile("/proc/net/route"); err == nil {
		lines := strings.Split(string(raw), "\n")
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[1] != "00000000" {
				continue
			}
			gateway, err := strconv.ParseUint(fields[2], 16, 32)
			if err != nil || gateway == 0 {
				continue
			}
			buf := make([]byte, 4)
			binary.LittleEndian.PutUint32(buf, uint32(gateway))
			add(net.IP(buf).String())
		}
	}

	// Advanced escape hatch for runtimes whose ingress proxy is not the default
	// gateway. Values are comma-separated exact IPs/CIDRs and are only consulted
	// on hosts that explicitly enable a trusted proxy provider.
	for _, value := range strings.Split(os.Getenv("ZENTPROXY_TRUSTED_TRANSPORT_HOPS"), ",") {
		add(value)
	}
	sort.Strings(out)
	return out
}

var (
	domainRE   = regexp.MustCompile(`^(?:\*\.)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$`)
	hostnameRE = regexp.MustCompile(`^[a-zA-Z0-9_](?:[a-zA-Z0-9_.-]{0,251}[a-zA-Z0-9_])?$`)
)

func ValidateHost(in model.HostInput) error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 120 {
		return fmt.Errorf("name is required and must be at most 120 characters")
	}
	if len(in.Domains) == 0 || len(in.Domains) > 50 {
		return fmt.Errorf("at least one and at most 50 domains are required")
	}
	seen := map[string]bool{}
	for _, d := range in.Domains {
		d = normalizeServerName(d)
		if !validServerName(d) {
			return fmt.Errorf("invalid domain or IP: %s", d)
		}
		if seen[d] {
			return fmt.Errorf("duplicate domain: %s", d)
		}
		seen[d] = true
	}
	if in.Scheme != "http" && in.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https")
	}
	if in.ForwardPort < 1 || in.ForwardPort > 65535 {
		return fmt.Errorf("forward_port must be between 1 and 65535")
	}
	h := strings.TrimSpace(in.ForwardHost)
	if h == "" || (!hostnameRE.MatchString(h) && net.ParseIP(strings.Trim(h, "[]")) == nil) {
		return fmt.Errorf("invalid forward_host")
	}
	return nil
}

func normalizeHostInput(in model.HostInput) model.HostInput {
	in.Name = strings.TrimSpace(in.Name)
	in.Scheme = strings.ToLower(strings.TrimSpace(in.Scheme))
	in.ForwardHost = strings.TrimSpace(in.ForwardHost)
	for i := range in.Domains {
		in.Domains[i] = normalizeServerName(in.Domains[i])
	}
	sort.Strings(in.Domains)
	return in
}

func normalizeServerName(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if ip := net.ParseIP(strings.Trim(v, "[]")); ip != nil {
		return ip.String()
	}
	return v
}

func validServerName(v string) bool {
	if v == "" || strings.ContainsAny(v, " \t\r\n;{}\\/") {
		return false
	}
	if net.ParseIP(strings.Trim(v, "[]")) != nil {
		return true
	}
	if strings.HasPrefix(v, "*.") {
		return domainRE.MatchString(v)
	}
	return domainRE.MatchString(v) || hostnameRE.MatchString(v)
}

func NormalizeAndValidate(in model.HostInput) (model.HostInput, error) {
	in = normalizeHostInput(in)
	return in, ValidateHost(in)
}

func CheckDomainConflicts(hosts []model.Host, domains []string, excludeID int64) error {
	wanted := make(map[string]struct{}, len(domains))
	for _, domain := range domains {
		wanted[strings.ToLower(strings.TrimSpace(domain))] = struct{}{}
	}
	for _, host := range hosts {
		if host.ID == excludeID {
			continue
		}
		for _, domain := range host.Domains {
			normalized := strings.ToLower(strings.TrimSpace(domain))
			if _, exists := wanted[normalized]; exists {
				return fmt.Errorf("domain %s is already assigned to proxy host %q", normalized, host.Name)
			}
		}
	}
	return nil
}

func (m *Manager) runtimePIDPath() string {
	return filepath.Join(m.dataDir, "nginx", "system", "openresty.pid")
}

func (m *Manager) testPIDPath() string {
	return filepath.Join(m.dataDir, "nginx", "system", "openresty-test.pid")
}

func (m *Manager) runtimePrefix() string {
	return filepath.Join(m.dataDir, "nginx", "runtime") + string(os.PathSeparator)
}

func pidFileProcessRunning(path string) (bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 0 {
		_ = os.Remove(path)
		return false, nil
	}

	err = syscall.Kill(pid, 0)
	switch {
	case err == nil, errors.Is(err, syscall.EPERM):
		return true, nil
	case errors.Is(err, syscall.ESRCH):
		_ = os.Remove(path)
		return false, nil
	default:
		return false, err
	}
}

func (m *Manager) ReopenLogs() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	binary := "/usr/local/openresty/bin/openresty"
	if _, err := os.Stat(binary); err != nil {
		return nil
	}
	running, err := pidFileProcessRunning(m.runtimePIDPath())
	if err != nil {
		return fmt.Errorf("proxy process check failed: %w", err)
	}
	if !running {
		return nil
	}
	path := filepath.Join(m.dataDir, "nginx", "nginx.conf")
	cmd := exec.Command(binary, "-p", m.runtimePrefix(), "-e", "stderr", "-s", "reopen", "-c", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("proxy log reopen failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *Manager) Apply() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	hosts, err := m.store.ListHosts()
	if err != nil {
		return err
	}
	redirects, err := m.store.ListRedirectHosts()
	if err != nil {
		return err
	}
	deadHosts, err := m.store.ListDeadHosts()
	if err != nil {
		return err
	}
	streams, err := m.store.ListStreams()
	if err != nil {
		return err
	}
	accessLists, err := m.store.ListAccessLists()
	if err != nil {
		return err
	}
	accessMap := make(map[int64]model.AccessList, len(accessLists))
	for _, a := range accessLists {
		accessMap[a.ID] = a
	}
	providers, err := m.store.ListProviders()
	if err != nil {
		return err
	}
	providerMap := make(map[int64]model.TrustedProxyProvider, len(providers))
	for _, p := range providers {
		providerMap[p.ID] = p
	}
	zentLoop, err := m.store.GetZentLoop()
	if err != nil {
		return err
	}
	certs, err := m.store.ListCertificates()
	if err != nil {
		return err
	}
	certMap := make(map[int64]model.Certificate, len(certs))
	for _, c := range certs {
		certMap[c.ID] = c
	}

	dir := filepath.Join(m.dataDir, "nginx")
	systemDir := filepath.Join(dir, "system")
	runtimeDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(systemDir, 0o750); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(runtimeDir, "logs"), 0o750); err != nil {
		return err
	}

	runtimePID := m.runtimePIDPath()
	conf, err := m.render(hosts, redirects, deadHosts, streams, accessMap, providerMap, certMap, zentLoop, runtimePID, m.trustedTransportHops)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "nginx.conf")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, conf, 0o640); err != nil {
		return err
	}

	binary := "/usr/local/openresty/bin/openresty"
	if _, err := os.Stat(binary); err == nil {
		testPID := m.testPIDPath()
		testConf, renderErr := m.render(hosts, redirects, deadHosts, streams, accessMap, providerMap, certMap, zentLoop, testPID, m.trustedTransportHops)
		if renderErr != nil {
			_ = os.Remove(tmp)
			return renderErr
		}
		testPath := filepath.Join(systemDir, "nginx-test.conf")
		if err := os.WriteFile(testPath, testConf, 0o640); err != nil {
			_ = os.Remove(tmp)
			return err
		}
		_ = os.Remove(testPID)
		cmd := exec.Command(binary, "-p", m.runtimePrefix(), "-e", "stderr", "-t", "-c", testPath)
		out, testErr := cmd.CombinedOutput()
		_ = os.Remove(testPID)
		_ = os.Remove(testPath)
		if testErr != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("proxy configuration test failed: %v: %s", testErr, strings.TrimSpace(string(out)))
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}

	running, err := pidFileProcessRunning(runtimePID)
	if err != nil {
		return fmt.Errorf("proxy process check failed: %w", err)
	}
	if running {
		cmd := exec.Command(binary, "-p", m.runtimePrefix(), "-e", "stderr", "-s", "reload", "-c", path)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("proxy reload failed: %v: %s", err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func (m *Manager) render(hosts []model.Host, redirects []model.RedirectHost, deadHosts []model.DeadHost, streams []model.Stream, accessLists map[int64]model.AccessList, providers map[int64]model.TrustedProxyProvider, certificates map[int64]model.Certificate, zentLoop model.ZentLoopConfig, pidPath string, trustedTransportHops []string) ([]byte, error) {
	var b bytes.Buffer
	data := nginxQuote(m.dataDir)
	pid := nginxQuote(pidPath)
	fmt.Fprintf(&b, `worker_processes auto;
error_log %s/logs/openresty-error.log warn;
pid %s;

events { worker_connections 4096; }

http {
    include /usr/local/openresty/nginx/conf/mime.types;
    default_type application/octet-stream;
    server_tokens off;
    sendfile on;
    tcp_nopush on;
    keepalive_timeout 65;
    client_max_body_size 0;
    client_body_temp_path %s/nginx/tmp/client_body;
    proxy_temp_path %s/nginx/tmp/proxy;
    fastcgi_temp_path %s/nginx/tmp/fastcgi;
    uwsgi_temp_path %s/nginx/tmp/uwsgi;
    scgi_temp_path %s/nginx/tmp/scgi;
    resolver 127.0.0.11 valid=30s ipv6=off;
    proxy_cache_path %s/cache levels=1:2 keys_zone=zentproxy_cache:10m max_size=1g inactive=60m use_temp_path=off;

    # The geo lookup must use $realip_remote_addr, not $remote_addr. The latter
    # can already be rewritten by ngx_http_realip_module before lazy variables
    # are evaluated. $realip_remote_addr preserves the original TCP/container
    # transport peer and therefore lets us reliably identify the Docker/NAT hop.
    geo $realip_remote_addr $zp_transport_peer {
        default 0;
__ZP_TRANSPORT_HOPS__    }

    # Mark only hosts that explicitly selected Cloudflare as their trusted proxy
    # provider. This prevents CF-Connecting-IP from being trusted on unrelated
    # hosts even when they share the same local Docker transport hop.
    map $host $zp_cloudflare_host {
        hostnames;
        default 0;
__ZP_CLOUDFLARE_HOSTS__    }

    # Canonical client identity. Docker Desktop and similar published-port NAT
    # can hide Cloudflare's TCP source address behind a local gateway. For hosts
    # that explicitly selected Cloudflare, CF-Connecting-IP is therefore the
    # authoritative client identity whenever it is present. Unrelated hosts never
    # trust this header. The original transport peer remains available separately
    # for diagnostics and network policy.
    map "$zp_cloudflare_host:$http_cf_connecting_ip" $zp_client_ip {
        default $remote_addr;
        ~^1:.+ $http_cf_connecting_ip;
    }

    log_format zentproxy_json escape=json '{"ts":"$time_iso8601","host":"$host","ip":"$zp_client_ip","method":"$request_method","path":"$uri","query":"","status":$status,"bytes":$body_bytes_sent,"request_time":"$request_time","upstream_time":"$upstream_response_time","user_agent":"$http_user_agent","referer":"$http_referer","http_version":"$server_protocol","tls_version":"$ssl_protocol"}';
    log_format zentproxy_json_query escape=json '{"ts":"$time_iso8601","host":"$host","ip":"$zp_client_ip","method":"$request_method","path":"$uri","query":"$args","status":$status,"bytes":$body_bytes_sent,"request_time":"$request_time","upstream_time":"$upstream_response_time","user_agent":"$http_user_agent","referer":"$http_referer","http_version":"$server_protocol","tls_version":"$ssl_protocol"}';

    access_log off;

    map $http_upgrade $connection_upgrade {
        default upgrade;
        '' close;
    }

    map $http_x_forwarded_proto $zp_forwarded_proto {
        default $http_x_forwarded_proto;
        '' $scheme;
    }

    map $host $zp_known_host {
        hostnames;
        default 0;
__ZP_KNOWN_HOSTS__    }

`, data, pid, data, data, data, data, data, data)

	known := map[string]bool{}
	for _, host := range hosts {
		if !host.Enabled {
			continue
		}
		for _, domain := range host.Domains {
			known[domain] = true
		}
	}
	for _, host := range redirects {
		if !host.Enabled {
			continue
		}
		for _, domain := range host.Domains {
			known[domain] = true
		}
	}
	for _, host := range deadHosts {
		if !host.Enabled {
			continue
		}
		for _, domain := range host.Domains {
			known[domain] = true
		}
	}
	knownDomains := make([]string, 0, len(known))
	for domain := range known {
		knownDomains = append(knownDomains, domain)
	}
	sort.Strings(knownDomains)
	var knownLines strings.Builder
	for _, domain := range knownDomains {
		fmt.Fprintf(&knownLines, "        %s 1;\n", domain)
	}
	confHead := strings.Replace(b.String(), "__ZP_KNOWN_HOSTS__", knownLines.String(), 1)

	// Resolve Cloudflare trust by requested host name before analytics/proxy
	// headers are evaluated. This keeps the canonical-IP decision independent of
	// the real_ip module's rewrite timing.
	cloudflareDomains := map[string]bool{}
	for _, host := range hosts {
		if !host.Enabled || host.TrustedProxyProviderID == nil {
			continue
		}
		p, ok := providers[*host.TrustedProxyProviderID]
		if !ok || !strings.EqualFold(strings.TrimSpace(p.Header), "CF-Connecting-IP") {
			continue
		}
		for _, domain := range host.Domains {
			cloudflareDomains[domain] = true
		}
	}
	var cloudflareLines strings.Builder
	cloudflareNames := make([]string, 0, len(cloudflareDomains))
	for domain := range cloudflareDomains {
		cloudflareNames = append(cloudflareNames, domain)
	}
	sort.Strings(cloudflareNames)
	for _, domain := range cloudflareNames {
		fmt.Fprintf(&cloudflareLines, "        %s 1;\n", domain)
	}
	confHead = strings.Replace(confHead, "__ZP_CLOUDFLARE_HOSTS__", cloudflareLines.String(), 1)

	var transportLines strings.Builder
	for _, cidr := range trustedTransportHops {
		fmt.Fprintf(&transportLines, "        %s 1;\n", cidr)
	}
	confHead = strings.Replace(confHead, "__ZP_TRANSPORT_HOPS__", transportLines.String(), 1)
	b.Reset()
	b.WriteString(confHead)

	if zentLoop.Enabled {
		for _, h := range hosts {
			if !h.Enabled {
				continue
			}
			routeCIDRs, blockCIDRs, _, _, _, _ := zentLoopRulesForHost(zentLoop, h.ID)
			if len(routeCIDRs) > 0 {
				fmt.Fprintf(&b, "    geo $zp_client_ip $zp_zentloop_route_%d {\n        default 0;\n", h.ID)
				for _, cidr := range routeCIDRs {
					fmt.Fprintf(&b, "        %s 1;\n", cidr)
				}
				b.WriteString("    }\n\n")
			}
			if len(blockCIDRs) > 0 {
				fmt.Fprintf(&b, "    geo $zp_client_ip $zp_zentloop_block_%d {\n        default 0;\n", h.ID)
				for _, cidr := range blockCIDRs {
					fmt.Fprintf(&b, "        %s 1;\n", cidr)
				}
				b.WriteString("    }\n\n")
			}
		}
	}

	// Unknown host handling is deliberately separate from normal upstream failures.
	fmt.Fprintf(&b, `    server {
        listen 80 default_server;
        server_name _;
        access_log %s/logs/access.jsonl zentproxy_json;
        location ^~ /.well-known/acme-challenge/ { root %s/acme-webroot; try_files $uri =404; access_log off; }
`, data, data)
	if zentLoop.Enabled {
		b.WriteString(`        location / {
            proxy_pass http://127.0.0.1:18081;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $zp_client_ip;
            proxy_set_header X-Forwarded-For $zp_client_ip;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-Host $host;
        }
`)
	} else {
		b.WriteString("        location / { return 404; }\n")
	}
	b.WriteString("    }\n\n")

	// HTTPS catch-all uses a local self-signed certificate only to terminate unknown SNI.
	fmt.Fprintf(&b, `    server {
        listen 443 ssl default_server;
        server_name _;
        ssl_certificate %s/certs/default/fullchain.pem;
        ssl_certificate_key %s/certs/default/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        access_log %s/logs/access.jsonl zentproxy_json;
        if ($zp_known_host = 1) { return 421; }
`, data, data, data)
	if zentLoop.Enabled {
		b.WriteString(`        location / {
            proxy_pass http://127.0.0.1:18081;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $zp_client_ip;
            proxy_set_header X-Forwarded-For $zp_client_ip;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-Host $host;
        }
`)
	} else {
		b.WriteString("        location / { return 404; }\n")
	}
	b.WriteString("    }\n\n")

	for _, h := range hosts {
		if !h.Enabled {
			continue
		}
		if err := ValidateStoredHost(h); err != nil {
			return nil, fmt.Errorf("host %d: %w", h.ID, err)
		}
		b.WriteString(renderHost(h, accessLists, providers, certificates, zentLoop, m.dataDir, trustedTransportHops))
	}
	for _, h := range redirects {
		if !h.Enabled {
			continue
		}
		b.WriteString(renderRedirectHost(h, certificates, m.dataDir))
	}
	for _, h := range deadHosts {
		if !h.Enabled {
			continue
		}
		b.WriteString(renderDeadHost(h, certificates, m.dataDir))
	}
	b.WriteString("}\n")
	if len(streams) > 0 {
		b.WriteString(renderStreams(streams, certificates))
	}
	return b.Bytes(), nil
}

func ValidateStoredHost(h model.Host) error {
	return ValidateHost(model.HostInput{Name: h.Name, Domains: h.Domains, Scheme: h.Scheme, ForwardHost: h.ForwardHost, ForwardPort: h.ForwardPort, Enabled: h.Enabled, WebSockets: h.WebSockets, PreserveHost: h.PreserveHost, StatisticsEnabled: h.StatisticsEnabled, StoreQueryString: h.StoreQueryString, TrustedProxyProviderID: h.TrustedProxyProviderID, AccessListID: h.AccessListID, BlockCommonExploits: h.BlockCommonExploits, CertificateID: h.CertificateID, SSLForced: h.SSLForced, HTTP2Support: h.HTTP2Support, HSTSEnabled: h.HSTSEnabled, HSTSSubdomains: h.HSTSSubdomains, CachingEnabled: h.CachingEnabled, TrustForwardedProto: h.TrustForwardedProto, AdvancedConfig: h.AdvancedConfig, CustomLocations: h.CustomLocations})
}

func renderHost(h model.Host, accessLists map[int64]model.AccessList, providers map[int64]model.TrustedProxyProvider, certificates map[int64]model.Certificate, zentLoop model.ZentLoopConfig, dataDir string, trustedTransportHops []string) string {
	var cert *model.Certificate
	if h.CertificateID != nil {
		if c, ok := certificates[*h.CertificateID]; ok {
			cert = &c
		}
	}
	var b strings.Builder
	b.WriteString(renderHostServer(h, accessLists, providers, zentLoop, dataDir, false, cert, trustedTransportHops))
	if cert != nil && cert.CertPath != "" && cert.KeyPath != "" {
		b.WriteString(renderHostServer(h, accessLists, providers, zentLoop, dataDir, true, cert, trustedTransportHops))
	}
	return b.String()
}

func renderHostServer(h model.Host, accessLists map[int64]model.AccessList, providers map[int64]model.TrustedProxyProvider, zentLoop model.ZentLoopConfig, dataDir string, tlsEnabled bool, cert *model.Certificate, trustedTransportHops []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "    # host:%d %s\n    server {\n", h.ID, safeComment(h.Name))
	if tlsEnabled {
		b.WriteString("        listen 443 ssl;\n")
		if h.HTTP2Support {
			b.WriteString("        http2 on;\n")
		}
		fmt.Fprintf(&b, "        ssl_certificate %s;\n        ssl_certificate_key %s;\n        ssl_protocols TLSv1.2 TLSv1.3;\n", nginxPath(cert.CertPath), nginxPath(cert.KeyPath))
		if h.HSTSEnabled {
			maxAge := "31536000"
			subs := ""
			if h.HSTSSubdomains {
				subs = "; includeSubDomains"
			}
			fmt.Fprintf(&b, "        add_header Strict-Transport-Security \"max-age=%s%s\" always;\n", maxAge, subs)
		}
	} else {
		b.WriteString("        listen 80;\n")
	}
	fmt.Fprintf(&b, "        server_name %s;\n", strings.Join(h.Domains, " "))
	if h.StatisticsEnabled {
		format := "zentproxy_json"
		if h.StoreQueryString {
			format = "zentproxy_json_query"
		}
		fmt.Fprintf(&b, "        access_log %s/logs/access.jsonl %s;\n", nginxQuote(dataDir), format)
	} else {
		b.WriteString("        access_log off;\n")
	}
	b.WriteString("        location ^~ /.well-known/acme-challenge/ { root " + nginxQuote(dataDir) + "/acme-webroot; try_files $uri =404; access_log off; }\n")
	if !tlsEnabled && h.SSLForced && cert != nil {
		b.WriteString("        location / { return 301 https://$host$request_uri; }\n    }\n\n")
		return b.String()
	}
	if h.TrustedProxyProviderID != nil {
		if p, ok := providers[*h.TrustedProxyProviderID]; ok {
			for _, cidr := range p.CIDRs {
				fmt.Fprintf(&b, "        set_real_ip_from %s;\n", cidr)
			}
			// A container runtime may SNAT published-port traffic before OpenResty,
			// making the immediate peer a local gateway (for example Docker Desktop).
			// Trust only detected/explicit exact transport hops, and only when this
			// host explicitly selected a trusted proxy provider.
			for _, cidr := range trustedTransportHops {
				fmt.Fprintf(&b, "        set_real_ip_from %s;\n", cidr)
			}
			if p.Header != "" {
				fmt.Fprintf(&b, "        real_ip_header %s;\n        real_ip_recursive on;\n", p.Header)
			}
		}
	}
	if zentLoop.Enabled {
		routeCIDRs, blockCIDRs, routeExact, routePrefix, blockExact, blockPrefix := zentLoopRulesForHost(zentLoop, h.ID)
		if len(routeCIDRs)+len(routeExact)+len(routePrefix) > 0 {
			b.WriteString("        error_page 418 = @zentproxy_zentloop;\n")
		}
		if len(blockCIDRs) > 0 {
			fmt.Fprintf(&b, "        if ($zp_zentloop_block_%d = 1) { return 403; }\n", h.ID)
		}
		if len(routeCIDRs) > 0 {
			fmt.Fprintf(&b, "        if ($zp_zentloop_route_%d = 1) { return 418; }\n", h.ID)
		}
		for _, path := range blockExact {
			fmt.Fprintf(&b, "        location = %s { return 403; }\n", path)
		}
		for _, path := range blockPrefix {
			fmt.Fprintf(&b, "        location ^~ %s { return 403; }\n", path)
		}
		for _, path := range routeExact {
			fmt.Fprintf(&b, "        location = %s { return 418; }\n", path)
		}
		for _, path := range routePrefix {
			fmt.Fprintf(&b, "        location ^~ %s { return 418; }\n", path)
		}
		if len(routeCIDRs)+len(routeExact)+len(routePrefix) > 0 {
			b.WriteString("        location @zentproxy_zentloop {\n            proxy_pass http://127.0.0.1:18081;\n            proxy_http_version 1.1;\n            proxy_set_header Host $host;\n            proxy_set_header X-Real-IP $zp_client_ip;\n            proxy_set_header X-Forwarded-For $zp_client_ip;\n            proxy_set_header X-Forwarded-Proto $scheme;\n            proxy_set_header X-Forwarded-Host $host;\n            proxy_set_header X-ZentLoop-Catch-All 0;\n        }\n")
		}
	}
	if h.AccessListID != nil {
		if a, ok := accessLists[*h.AccessListID]; ok {
			if len(a.Rules) > 0 || (a.AuthEnabled && a.AuthFile != "") {
				if a.SatisfyAny {
					b.WriteString("        satisfy any;\n")
				} else {
					b.WriteString("        satisfy all;\n")
				}
			}
			for _, rule := range a.Rules {
				directive := strings.ToLower(strings.TrimSpace(rule.Directive))
				address := strings.TrimSpace(rule.Address)
				if (directive == "allow" || directive == "deny") && validAccessAddress(address) {
					fmt.Fprintf(&b, "        %s %s;\n", directive, address)
				}
			}
			if a.AuthEnabled && strings.TrimSpace(a.AuthFile) != "" {
				fmt.Fprintf(&b, "        auth_basic %q;\n        auth_basic_user_file %s;\n", "Authorization required", nginxFilePath(a.AuthFile, "/data/access-lists/invalid"))
			}
			if !a.PassAuth {
				b.WriteString("        proxy_set_header Authorization \"\";\n")
			}
		}
	}
	if h.BlockCommonExploits {
		b.WriteString("        location ~* ^/(?:\\.git|\\.svn|\\.hg)(?:/|$) { return 404; }\n        location ~* \\.(?:bak|old|orig|swp|sql)$ { return 404; }\n")
	}
	for _, loc := range h.CustomLocations {
		b.WriteString(renderLocation(h, loc, "        "))
	}
	advancedConfig := h.AdvancedConfig
	if h.TrustedProxyProviderID != nil {
		advancedConfig = stripManagedRealIPDirectives(advancedConfig)
	}
	if strings.TrimSpace(advancedConfig) != "" {
		b.WriteString(indentConfig(advancedConfig, "        "))
		if !strings.HasSuffix(advancedConfig, "\n") {
			b.WriteByte('\n')
		}
	}
	if !advancedHasDefaultLocation(h.AdvancedConfig) {
		b.WriteString(renderDefaultLocation(h, "        "))
	}
	b.WriteString("    }\n\n")
	return b.String()
}

func renderDefaultLocation(h model.Host, indent string) string {
	return renderLocation(h, model.CustomLocation{Path: "/", Scheme: h.Scheme, ForwardHost: h.ForwardHost, ForwardPort: h.ForwardPort}, indent)
}

func renderLocation(h model.Host, loc model.CustomLocation, indent string) string {
	path := strings.TrimSpace(loc.Path)
	if path == "" {
		path = "/"
	}
	if strings.ContainsAny(path, "\r\n{};") {
		return ""
	}
	scheme := strings.ToLower(strings.TrimSpace(loc.Scheme))
	if scheme != "https" {
		scheme = "http"
	}
	host := strings.TrimSpace(loc.ForwardHost)
	if host == "" {
		host = h.ForwardHost
	}
	port := loc.ForwardPort
	if port < 1 {
		port = h.ForwardPort
	}
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil && strings.Contains(ip.String(), ":") {
		host = "[" + ip.String() + "]"
	}
	forwardPath := strings.TrimSpace(loc.ForwardPath)
	if forwardPath != "" && !strings.HasPrefix(forwardPath, "/") {
		forwardPath = "/" + forwardPath
	}
	upstream := scheme + "://" + host + ":" + strconv.Itoa(port) + forwardPath
	var b strings.Builder
	fmt.Fprintf(&b, "%slocation %s {\n", indent, path)
	fmt.Fprintf(&b, "%s    proxy_pass %s;\n", indent, upstream)
	fmt.Fprintf(&b, "%s    proxy_http_version 1.1;\n", indent)
	if h.PreserveHost {
		fmt.Fprintf(&b, "%s    proxy_set_header Host $host;\n", indent)
	} else {
		fmt.Fprintf(&b, "%s    proxy_set_header Host $proxy_host;\n", indent)
	}
	fmt.Fprintf(&b, "%s    proxy_set_header X-Real-IP $zp_client_ip;\n%s    proxy_set_header X-Forwarded-For $zp_client_ip;\n", indent, indent)
	if h.TrustForwardedProto {
		fmt.Fprintf(&b, "%s    proxy_set_header X-Forwarded-Proto $zp_forwarded_proto;\n", indent)
	} else {
		fmt.Fprintf(&b, "%s    proxy_set_header X-Forwarded-Proto $scheme;\n", indent)
	}
	fmt.Fprintf(&b, "%s    proxy_set_header X-Forwarded-Host $host;\n", indent)
	if h.WebSockets {
		fmt.Fprintf(&b, "%s    proxy_set_header Upgrade $http_upgrade;\n%s    proxy_set_header Connection $connection_upgrade;\n", indent, indent)
	}
	if h.CachingEnabled {
		fmt.Fprintf(&b, "%s    proxy_cache zentproxy_cache;\n%s    proxy_cache_valid 200 10m;\n", indent, indent)
	}
	if strings.TrimSpace(loc.AdvancedConfig) != "" {
		b.WriteString(indentConfig(loc.AdvancedConfig, indent+"    "))
	}
	fmt.Fprintf(&b, "%s}\n", indent)
	return b.String()
}

func zentLoopRulesForHost(cfg model.ZentLoopConfig, hostID int64) (routeCIDRs, blockCIDRs, routeExact, routePrefix, blockExact, blockPrefix []string) {
	lists := map[string][]string{}
	for _, l := range cfg.IPLists {
		lists[strings.ToLower(strings.TrimSpace(l.Name))] = l.Entries
	}
	applies := func(ids []int64) bool {
		if len(ids) == 0 {
			return true
		}
		for _, id := range ids {
			if id == hostID {
				return true
			}
		}
		return false
	}
	seen := map[string]bool{}
	add := func(dst *[]string, v string) {
		k := fmt.Sprintf("%p:%s", dst, v)
		if !seen[k] {
			*dst = append(*dst, v)
			seen[k] = true
		}
	}
	for _, r := range cfg.Rules {
		if !r.Enabled || !applies(r.HostIDs) {
			continue
		}
		action := strings.ToLower(strings.TrimSpace(r.Action))
		match := strings.ToLower(strings.TrimSpace(r.Match))
		value := strings.TrimSpace(r.Value)
		switch match {
		case "source_ip_list":
			for _, e := range lists[strings.ToLower(value)] {
				if action == "block" {
					add(&blockCIDRs, e)
				} else if action == "zentloop" {
					add(&routeCIDRs, e)
				}
			}
		case "path_exact":
			if action == "block" {
				add(&blockExact, value)
			} else if action == "zentloop" {
				add(&routeExact, value)
			}
		case "path_prefix":
			if action == "block" {
				add(&blockPrefix, value)
			} else if action == "zentloop" {
				add(&routePrefix, value)
			}
		}
	}
	sort.Strings(routeCIDRs)
	sort.Strings(blockCIDRs)
	sort.Strings(routeExact)
	sort.Strings(routePrefix)
	sort.Strings(blockExact)
	sort.Strings(blockPrefix)
	return
}

func validAccessAddress(v string) bool {
	v = strings.TrimSpace(v)
	if v == "all" {
		return true
	}
	if strings.ContainsAny(v, " \t\r\n;{}") {
		return false
	}
	if net.ParseIP(v) != nil {
		return true
	}
	if _, _, err := net.ParseCIDR(v); err == nil {
		return true
	}
	return hostnameRE.MatchString(v)
}

func renderRedirectHost(h model.RedirectHost, certificates map[int64]model.Certificate, dataDir string) string {
	var cert *model.Certificate
	if h.CertificateID != nil {
		if c, ok := certificates[*h.CertificateID]; ok {
			cert = &c
		}
	}
	var b strings.Builder
	b.WriteString(renderRedirectServer(h, dataDir, false, cert))
	if cert != nil && cert.CertPath != "" && cert.KeyPath != "" {
		b.WriteString(renderRedirectServer(h, dataDir, true, cert))
	}
	return b.String()
}

func renderRedirectServer(h model.RedirectHost, dataDir string, tlsEnabled bool, cert *model.Certificate) string {
	var b strings.Builder
	fmt.Fprintf(&b, "    # redirect:%d\n    server {\n", h.ID)
	if tlsEnabled {
		b.WriteString("        listen 443 ssl;\n")
		if h.HTTP2Support {
			b.WriteString("        http2 on;\n")
		}
		fmt.Fprintf(&b, "        ssl_certificate %s;\n        ssl_certificate_key %s;\n        ssl_protocols TLSv1.2 TLSv1.3;\n", nginxPath(cert.CertPath), nginxPath(cert.KeyPath))
		if h.HSTSEnabled {
			subs := ""
			if h.HSTSSubdomains {
				subs = "; includeSubDomains"
			}
			fmt.Fprintf(&b, "        add_header Strict-Transport-Security \"max-age=31536000%s\" always;\n", subs)
		}
	} else {
		b.WriteString("        listen 80;\n")
	}
	fmt.Fprintf(&b, "        server_name %s;\n", strings.Join(h.Domains, " "))
	b.WriteString("        location ^~ /.well-known/acme-challenge/ { root " + nginxQuote(dataDir) + "/acme-webroot; try_files $uri =404; access_log off; }\n")
	if !tlsEnabled && h.SSLForced && cert != nil {
		b.WriteString("        location / { return 301 https://$host$request_uri; }\n    }\n\n")
		return b.String()
	}
	if h.BlockExploits {
		b.WriteString("        location ~* ^/(?:\\.git|\\.svn|\\.hg)(?:/|$) { return 404; }\n")
	}
	if strings.TrimSpace(h.AdvancedConfig) != "" {
		b.WriteString(indentConfig(h.AdvancedConfig, "        "))
	}
	scheme := strings.ToLower(strings.TrimSpace(h.ForwardScheme))
	if scheme != "http" && scheme != "https" {
		scheme = "$scheme"
	}
	target := scheme + "://" + strings.TrimSpace(h.ForwardDomainName)
	if h.PreservePath {
		target += "$request_uri"
	}
	fmt.Fprintf(&b, "        location / { return %d %s; }\n    }\n\n", h.ForwardHTTPCode, target)
	return b.String()
}

func renderDeadHost(h model.DeadHost, certificates map[int64]model.Certificate, dataDir string) string {
	var cert *model.Certificate
	if h.CertificateID != nil {
		if c, ok := certificates[*h.CertificateID]; ok {
			cert = &c
		}
	}
	var b strings.Builder
	for _, tlsEnabled := range []bool{false, true} {
		if tlsEnabled && cert == nil {
			continue
		}
		fmt.Fprintf(&b, "    # dead:%d\n    server {\n", h.ID)
		if tlsEnabled {
			b.WriteString("        listen 443 ssl;\n")
			if h.HTTP2Support {
				b.WriteString("        http2 on;\n")
			}
			fmt.Fprintf(&b, "        ssl_certificate %s;\n        ssl_certificate_key %s;\n        ssl_protocols TLSv1.2 TLSv1.3;\n", nginxPath(cert.CertPath), nginxPath(cert.KeyPath))
			if h.HSTSEnabled {
				subs := ""
				if h.HSTSSubdomains {
					subs = "; includeSubDomains"
				}
				fmt.Fprintf(&b, "        add_header Strict-Transport-Security \"max-age=31536000%s\" always;\n", subs)
			}
		} else {
			b.WriteString("        listen 80;\n")
		}
		fmt.Fprintf(&b, "        server_name %s;\n", strings.Join(h.Domains, " "))
		b.WriteString("        location ^~ /.well-known/acme-challenge/ { root " + nginxQuote(dataDir) + "/acme-webroot; try_files $uri =404; access_log off; }\n")
		if !tlsEnabled && h.SSLForced && cert != nil {
			b.WriteString("        location / { return 301 https://$host$request_uri; }\n    }\n\n")
			continue
		}
		if strings.TrimSpace(h.AdvancedConfig) != "" {
			b.WriteString(indentConfig(h.AdvancedConfig, "        "))
		}
		b.WriteString("        location / { return 404; }\n    }\n\n")
	}
	return b.String()
}

func renderStreams(streams []model.Stream, certificates map[int64]model.Certificate) string {
	var b strings.Builder
	b.WriteString("\nstream {\n")
	for _, s := range streams {
		if !s.Enabled {
			continue
		}
		host := strings.TrimSpace(s.ForwardHost)
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil && strings.Contains(ip.String(), ":") {
			host = "[" + ip.String() + "]"
		}
		upstream := host + ":" + strconv.Itoa(s.ForwardPort)
		if s.TCPForwarding {
			fmt.Fprintf(&b, "    # stream:%d tcp\n    server {\n        listen %d", s.ID, s.IncomingPort)
			if s.CertificateID != nil {
				if c, ok := certificates[*s.CertificateID]; ok {
					b.WriteString(" ssl")
					fmt.Fprintf(&b, ";\n        ssl_certificate %s;\n        ssl_certificate_key %s", nginxPath(c.CertPath), nginxPath(c.KeyPath))
				}
			}
			b.WriteString(";\n")
			fmt.Fprintf(&b, "        proxy_pass %s;\n    }\n", upstream)
		}
		if s.UDPForwarding {
			fmt.Fprintf(&b, "    # stream:%d udp\n    server {\n        listen %d udp;\n        proxy_pass %s;\n    }\n", s.ID, s.IncomingPort, upstream)
		}
	}
	b.WriteString("}\n")
	return b.String()
}

var defaultLocationRE = regexp.MustCompile(`(?m)^\s*location\s+(?:=|~\*?|\^~)?\s*/(?:\s|\{)`)

func stripManagedRealIPDirectives(v string) string {
	if strings.TrimSpace(v) == "" {
		return v
	}
	lines := strings.Split(v, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		managed := false
		for _, directive := range []string{"set_real_ip_from", "real_ip_header", "real_ip_recursive"} {
			if strings.HasPrefix(lower, directive) {
				rest := strings.TrimSpace(trimmed[len(directive):])
				if strings.HasSuffix(rest, ";") || strings.Contains(rest, "; #") || strings.Contains(rest, ";#") {
					managed = true
					break
				}
			}
		}
		if !managed {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

func advancedHasDefaultLocation(v string) bool {
	lines := strings.Split(v, "\n")
	var clean strings.Builder
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		clean.WriteString(line)
		clean.WriteByte('\n')
	}
	return defaultLocationRE.MatchString(clean.String())
}
func indentConfig(v, indent string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.ReplaceAll(v, "\r\n", "\n"), "\n") {
		if line == "" {
			b.WriteByte('\n')
		} else {
			b.WriteString(indent)
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}
func nginxFilePath(v, fallback string) string {
	v = strings.TrimSpace(v)
	if v == "" || strings.ContainsAny(v, "\r\n;\"") {
		return fallback
	}
	return v
}

func nginxPath(v string) string { return nginxFilePath(v, "/data/certs/default/fullchain.pem") }

func nginxQuote(v string) string {
	// Data dir comes from the local environment. Reject newline/control characters rather than trying to escape directives.
	v = strings.TrimSpace(v)
	v = strings.ReplaceAll(v, "\\", "/")
	if strings.ContainsAny(v, "\r\n;") {
		return "/data"
	}
	return v
}

func safeComment(v string) string { return strings.NewReplacer("\n", " ", "\r", " ").Replace(v) }

func IsNotFound(err error) bool { return err == sql.ErrNoRows }
