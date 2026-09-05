package proxy

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
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

	"github.com/ZentWorks/ZentProxy/internal/certificates"
	"github.com/ZentWorks/ZentProxy/internal/db"
	"github.com/ZentWorks/ZentProxy/internal/model"
)

type Manager struct {
	store                *db.Store
	dataDir              string
	trustedTransportHops []string
	analyticsIPMode      string
	nofileLimit          uint64
	mu                   sync.Mutex
}

type runtimeCapacity struct {
	WorkerConnections    int
	KeepalivePerUpstream int
	ZentLoopKeepalive    int
}

func currentOpenFileLimit() uint64 {
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err == nil && limit.Cur > 0 {
		return limit.Cur
	}
	return 1024
}

func computeRuntimeCapacity(nofile uint64, upstreamPools int) runtimeCapacity {
	if nofile == 0 {
		nofile = 1024
	}
	// Keep a small file-descriptor reserve for listeners, logs, DNS sockets and
	// other process internals. worker_connections counts client and upstream
	// connections, so it must stay below the inherited RLIMIT_NOFILE.
	reserve := nofile / 16
	if reserve < 64 {
		reserve = 64
	}
	available := nofile
	if available > reserve {
		available -= reserve
	} else {
		available = nofile / 2
	}
	if available > 16384 {
		available = 16384
	}
	if available < 64 {
		available = nofile
	}
	workerConnections := int(available)
	if workerConnections < 1 {
		workerConnections = 1
	}

	if upstreamPools < 1 {
		upstreamPools = 1
	}
	idleBudget := workerConnections / 4
	if idleBudget < 1 {
		idleBudget = 1
	}
	keepalive := idleBudget / upstreamPools
	if keepalive < 1 {
		keepalive = 1
	}
	if keepalive > 64 {
		keepalive = 64
	}
	zentLoopKeepalive := keepalive
	if zentLoopKeepalive > 16 {
		zentLoopKeepalive = 16
	}
	return runtimeCapacity{
		WorkerConnections:    workerConnections,
		KeepalivePerUpstream: keepalive,
		ZentLoopKeepalive:    zentLoopKeepalive,
	}
}

func (m *Manager) effectiveNofileLimit() uint64 {
	if m.nofileLimit > 0 {
		return m.nofileLimit
	}
	return currentOpenFileLimit()
}

func runtimeWorkDir() string {
	if value := strings.TrimSpace(os.Getenv("ZENTPROXY_RUNTIME_DIR")); value != "" {
		return filepath.Clean(value)
	}
	return "/tmp/zentproxy"
}

func analyticsLogPath() string {
	return filepath.Join(runtimeWorkDir(), "analytics", "events.spool")
}

func nginxTempDir() string {
	return filepath.Join(runtimeWorkDir(), "nginx", "tmp")
}

func proxyCacheDir() string {
	return filepath.Join(runtimeWorkDir(), "cache")
}

func nginxErrorLogPath() string {
	return filepath.Join(runtimeWorkDir(), "nginx", "error.log")
}

func NewManager(store *db.Store, dataDir string, analyticsIPMode ...string) *Manager {
	mode := "full"
	if len(analyticsIPMode) > 0 {
		switch strings.ToLower(strings.TrimSpace(analyticsIPMode[0])) {
		case "full", "anonymized", "disabled":
			mode = strings.ToLower(strings.TrimSpace(analyticsIPMode[0]))
		}
	}
	return &Manager{store: store, dataDir: dataDir, trustedTransportHops: detectTrustedTransportHops(), analyticsIPMode: mode, nofileLimit: currentOpenFileLimit()}
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

func validForwardHost(raw string) bool {
	h := strings.TrimSpace(raw)
	if h == "" {
		return false
	}
	return hostnameRE.MatchString(h) || net.ParseIP(strings.Trim(h, "[]")) != nil
}

func normalizeForwardHost(raw string) string {
	h := strings.TrimSpace(raw)
	if validForwardHost(h) {
		return h
	}
	// Compatibility repair for legacy custom-location rows that accidentally
	// persisted a URL-style trailing slash in forward_host (for example
	// "192.168.1.10/"). Only strip slashes when the remaining value is a valid
	// hostname/IP, so malformed input is never silently broadened.
	candidate := strings.TrimRight(h, "/")
	if candidate != h && validForwardHost(candidate) {
		return candidate
	}
	return h
}

func normalizeCustomLocation(loc model.CustomLocation, parent model.HostInput) model.CustomLocation {
	loc.Path = strings.TrimSpace(loc.Path)
	if loc.Path == "" {
		loc.Path = "/"
	}
	loc.Scheme = strings.ToLower(strings.TrimSpace(loc.Scheme))
	if loc.Scheme == "" {
		loc.Scheme = parent.Scheme
	}
	loc.ForwardHost = normalizeForwardHost(loc.ForwardHost)
	loc.ForwardPath = strings.TrimSpace(loc.ForwardPath)
	if loc.ForwardPath != "" && !strings.HasPrefix(loc.ForwardPath, "/") {
		loc.ForwardPath = "/" + loc.ForwardPath
	}
	return loc
}

func validateCustomLocation(loc model.CustomLocation, parent model.HostInput) error {
	path := strings.TrimSpace(loc.Path)
	if path == "" || !strings.HasPrefix(path, "/") || path == "/" || strings.ContainsAny(path, " \t\r\n;{}#$\\") {
		return fmt.Errorf("invalid custom location path: %s", path)
	}
	if loc.Scheme != "http" && loc.Scheme != "https" {
		return fmt.Errorf("custom location %s scheme must be http or https", path)
	}
	host := strings.TrimSpace(loc.ForwardHost)
	if host == "" {
		host = parent.ForwardHost
	}
	if !validForwardHost(host) {
		return fmt.Errorf("custom location %s has invalid forward_host", path)
	}
	port := loc.ForwardPort
	if port == 0 {
		port = parent.ForwardPort
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("custom location %s forward_port must be between 1 and 65535", path)
	}
	if fp := strings.TrimSpace(loc.ForwardPath); fp != "" {
		if !strings.HasPrefix(fp, "/") || strings.ContainsAny(fp, " \t\r\n;{}#$\\\"") {
			return fmt.Errorf("custom location %s has invalid forward_path", path)
		}
	}
	return nil
}

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
	if !validForwardHost(h) {
		return fmt.Errorf("invalid forward_host")
	}
	if len(in.CustomLocations) > 50 {
		return fmt.Errorf("at most 50 custom locations are allowed")
	}
	seenPaths := map[string]struct{}{}
	for _, loc := range in.CustomLocations {
		if err := validateCustomLocation(loc, in); err != nil {
			return err
		}
		key := strings.TrimSpace(loc.Path)
		if _, exists := seenPaths[key]; exists {
			return fmt.Errorf("duplicate custom location path: %s", key)
		}
		seenPaths[key] = struct{}{}
	}
	return nil
}

func normalizeHostInput(in model.HostInput) model.HostInput {
	in.Name = strings.TrimSpace(in.Name)
	in.Scheme = strings.ToLower(strings.TrimSpace(in.Scheme))
	in.ForwardHost = normalizeForwardHost(in.ForwardHost)
	for i := range in.CustomLocations {
		in.CustomLocations[i] = normalizeCustomLocation(in.CustomLocations[i], in)
	}
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

var commonCountrySecondLevels = map[string]struct{}{
	"ac": {}, "asn": {}, "co": {}, "com": {}, "edu": {}, "firm": {}, "gen": {}, "go": {}, "gov": {}, "id": {}, "ind": {}, "ltd": {}, "me": {}, "mil": {}, "net": {}, "ne": {}, "nom": {}, "or": {}, "org": {}, "plc": {}, "sch": {},
}

func registrableDomain(domain string) string {
	d := normalizeServerName(domain)
	d = strings.TrimPrefix(d, "*.")
	d = strings.TrimSuffix(d, ".")
	if d == "" || net.ParseIP(strings.Trim(d, "[]")) != nil {
		return ""
	}
	parts := strings.Split(d, ".")
	if len(parts) < 2 {
		return d
	}
	tld, sld := parts[len(parts)-1], parts[len(parts)-2]
	if len(tld) == 2 && len(parts) >= 3 {
		if _, ok := commonCountrySecondLevels[sld]; ok {
			return strings.Join(parts[len(parts)-3:], ".")
		}
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func zentLoopRootDomains(hosts []model.Host) []string {
	roots := map[string]struct{}{}
	for _, host := range hosts {
		if !host.Enabled {
			continue
		}
		for _, domain := range host.Domains {
			if root := registrableDomain(domain); root != "" {
				roots[root] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(roots))
	for root := range roots {
		out = append(out, root)
	}
	sort.Strings(out)
	return out
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

func (m *Manager) startupReadyPath() string {
	return filepath.Join(m.dataDir, "nginx", "system", "proxy-config.ready")
}

func (m *Manager) markStartupReadyLocked() error {
	path := m.startupReadyPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte("ready\n"), 0o640); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
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
	return m.applyLocked(nil)
}

// ApplyStartup is a fail-safe startup activation path. It first attempts the
// complete configuration. If OpenResty reports an unresolved upstream host,
// ZentProxy retries with only the affected Proxy Host(s) isolated onto a local
// fail-closed upstream. Their server_name/TLS/access boundaries stay present,
// so they cannot fall through to ZentLoop or another catch-all. The database is
// never modified by this fallback.
//
// If the failure is unrelated to an unresolved upstream, the last known-good
// nginx.conf is retained. On a fresh installation where no valid config exists,
// a minimal neutral 404 config is written so the container remains manageable.
func (m *Manager) ApplyStartup() ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	initialErr := m.applyLocked(nil)
	if initialErr == nil {
		return nil, nil
	}

	hosts, listErr := m.store.ListHosts()
	if listErr == nil {
		remaining := append([]model.Host(nil), hosts...)
		skippedSet := map[string]struct{}{}
		currentErr := initialErr
		for len(remaining) > 0 {
			upstreamHost := unresolvedUpstreamFromError(currentErr)
			if upstreamHost == "" {
				break
			}
			isolation, isolated := isolateHostsReferencingUpstream(remaining, upstreamHost)
			if len(isolated) == 0 {
				break
			}
			for _, name := range isolated {
				skippedSet[name] = struct{}{}
			}
			if degradedErr := m.applyLocked(isolation); degradedErr == nil {
				out := make([]string, 0, len(skippedSet))
				for name := range skippedSet {
					out = append(out, name)
				}
				sort.Strings(out)
				return out, initialErr
			} else {
				currentErr = degradedErr
				remaining = isolation
			}
		}
	}

	path := filepath.Join(m.dataDir, "nginx", "nginx.conf")
	if info, statErr := os.Stat(path); statErr == nil && info.Size() > 0 && m.existingConfigValidLocked(path) {
		if readyErr := m.markStartupReadyLocked(); readyErr != nil {
			return nil, fmt.Errorf("%v; last-known-good config is valid but startup readiness could not be published: %w", initialErr, readyErr)
		}
		return nil, initialErr
	}
	if fallbackErr := m.writeSafeFallbackLocked(); fallbackErr != nil {
		return nil, fmt.Errorf("%v; safe startup fallback failed: %w", initialErr, fallbackErr)
	}
	if readyErr := m.markStartupReadyLocked(); readyErr != nil {
		return nil, fmt.Errorf("%v; safe startup fallback is ready but startup readiness could not be published: %w", initialErr, readyErr)
	}
	return nil, initialErr
}

var unresolvedUpstreamRE = regexp.MustCompile(`host not found in upstream "([^"]+)"`)

func unresolvedUpstreamFromError(err error) string {
	if err == nil {
		return ""
	}
	match := unresolvedUpstreamRE.FindStringSubmatch(err.Error())
	if len(match) != 2 {
		return ""
	}
	value := strings.TrimSpace(match[1])
	if host, _, splitErr := net.SplitHostPort(value); splitErr == nil {
		return strings.Trim(strings.TrimSpace(host), "[]")
	}
	if i := strings.LastIndex(value, ":"); i > 0 && !strings.Contains(value[i+1:], ":") {
		return strings.Trim(strings.TrimSpace(value[:i]), "[]")
	}
	return strings.Trim(value, "[]")
}

func isolateHostsReferencingUpstream(hosts []model.Host, upstreamHost string) ([]model.Host, []string) {
	upstreamHost = strings.Trim(strings.TrimSpace(upstreamHost), "[]")
	out := append([]model.Host(nil), hosts...)
	isolated := make([]string, 0)
	for i := range out {
		h := &out[i]
		matches := false
		if h.Enabled {
			for _, name := range hostUpstreamNames(*h) {
				if strings.EqualFold(name, upstreamHost) {
					matches = true
					break
				}
			}
		}
		if !matches {
			continue
		}
		isolated = append(isolated, h.Name)
		h.Scheme = "http"
		h.ForwardHost = "127.0.0.1"
		h.ForwardPort = 9
		if len(h.CustomLocations) > 0 {
			locations := append([]model.CustomLocation(nil), h.CustomLocations...)
			for j := range locations {
				locations[j].Scheme = "http"
				locations[j].ForwardHost = "127.0.0.1"
				locations[j].ForwardPort = 9
			}
			h.CustomLocations = locations
		}
	}
	sort.Strings(isolated)
	return out, isolated
}

func hostUpstreamNames(h model.Host) []string {
	seen := map[string]struct{}{}
	add := func(raw string) {
		raw = strings.TrimSpace(strings.Trim(raw, "[]"))
		if raw == "" || net.ParseIP(raw) != nil {
			return
		}
		seen[raw] = struct{}{}
	}
	add(h.ForwardHost)
	for _, loc := range h.CustomLocations {
		name := strings.TrimSpace(loc.ForwardHost)
		if name == "" {
			name = h.ForwardHost
		}
		add(name)
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func (m *Manager) applyLocked(hostOverride []model.Host) error {
	hosts := hostOverride
	var err error
	if hostOverride == nil {
		hosts, err = m.store.ListHosts()
		if err != nil {
			return err
		}
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
	for _, h := range hosts {
		if h.Enabled && h.CertificateID != nil {
			if c, ok := certMap[*h.CertificateID]; !ok {
				return fmt.Errorf("host %d references missing certificate", h.ID)
			} else if err := certificates.ValidateDomains(c, h.Domains); err != nil {
				return fmt.Errorf("host %d certificate: %w", h.ID, err)
			}
		}
	}
	for _, h := range redirects {
		if h.Enabled && h.CertificateID != nil {
			if c, ok := certMap[*h.CertificateID]; !ok {
				return fmt.Errorf("redirect host %d references missing certificate", h.ID)
			} else if err := certificates.ValidateDomains(c, h.Domains); err != nil {
				return fmt.Errorf("redirect host %d certificate: %w", h.ID, err)
			}
		}
	}
	for _, h := range deadHosts {
		if h.Enabled && h.CertificateID != nil {
			if c, ok := certMap[*h.CertificateID]; !ok {
				return fmt.Errorf("404 host %d references missing certificate", h.ID)
			} else if err := certificates.ValidateDomains(c, h.Domains); err != nil {
				return fmt.Errorf("404 host %d certificate: %w", h.ID, err)
			}
		}
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
	for _, path := range []string{
		filepath.Dir(analyticsLogPath()),
		filepath.Join(nginxTempDir(), "client_body"),
		filepath.Join(nginxTempDir(), "proxy"),
		filepath.Join(nginxTempDir(), "fastcgi"),
		filepath.Join(nginxTempDir(), "uwsgi"),
		filepath.Join(nginxTempDir(), "scgi"),
		proxyCacheDir(),
	} {
		if err := os.MkdirAll(path, 0o750); err != nil {
			return err
		}
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
	if err := m.markStartupReadyLocked(); err != nil {
		return fmt.Errorf("proxy configuration activated but startup readiness could not be published: %w", err)
	}
	return nil
}

func (m *Manager) existingConfigValidLocked(path string) bool {
	binary := "/usr/local/openresty/bin/openresty"
	if _, err := os.Stat(binary); err != nil {
		// Unit/development environments may not contain OpenResty. The runtime
		// container always does, so retain the file here rather than deleting a
		// potentially valid last-known-good configuration without a validator.
		return true
	}
	cmd := exec.Command(binary, "-p", m.runtimePrefix(), "-e", "stderr", "-t", "-c", path)
	return cmd.Run() == nil
}

func (m *Manager) writeSafeFallbackLocked() error {
	dir := filepath.Join(m.dataDir, "nginx")
	if err := os.MkdirAll(filepath.Join(dir, "runtime", "logs"), 0o750); err != nil {
		return err
	}
	capacity := computeRuntimeCapacity(m.effectiveNofileLimit(), 1)
	conf := fmt.Sprintf(`worker_processes auto;
error_log %s error;
pid %s;

events { worker_connections %d; }

http {
    server_tokens off;
    access_log off;
    ssl_session_cache shared:ZentProxySSL:4m;
    ssl_session_timeout 1h;
    ssl_buffer_size 4k;
    server { listen 80 default_server backlog=8192; server_name _; return 404; }
    server {
        listen 443 ssl default_server backlog=8192;
        server_name _;
        ssl_certificate %s/certs/default/fullchain.pem;
        ssl_certificate_key %s/certs/default/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        return 404;
    }
}
`, nginxQuote(nginxErrorLogPath()), nginxQuote(m.runtimePIDPath()), capacity.WorkerConnections, nginxQuote(m.dataDir), nginxQuote(m.dataDir))
	path := filepath.Join(dir, "nginx.conf")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(conf), 0o640); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func (m *Manager) render(hosts []model.Host, redirects []model.RedirectHost, deadHosts []model.DeadHost, streams []model.Stream, accessLists map[int64]model.AccessList, providers map[int64]model.TrustedProxyProvider, certificateMap map[int64]model.Certificate, zentLoop model.ZentLoopConfig, pidPath string, trustedTransportHops []string) ([]byte, error) {
	normalizedHosts := make([]model.Host, len(hosts))
	copy(normalizedHosts, hosts)
	for i := range normalizedHosts {
		if !normalizedHosts[i].Enabled {
			continue
		}
		normalized, err := NormalizeStoredHost(normalizedHosts[i])
		if err != nil {
			return nil, fmt.Errorf("host %d: %w", normalizedHosts[i].ID, err)
		}
		normalizedHosts[i] = normalized
	}
	hosts = normalizedHosts
	proxyUpstreams := collectProxyUpstreams(hosts)
	poolCount := len(proxyUpstreams)
	if zentLoop.Enabled {
		poolCount++
	}
	capacity := computeRuntimeCapacity(m.effectiveNofileLimit(), poolCount)
	var b bytes.Buffer
	data := nginxQuote(m.dataDir)
	pid := nginxQuote(pidPath)
	fmt.Fprintf(&b, `worker_processes auto;
error_log %s error;
pid %s;

events {
    worker_connections %d;
}

http {
    include /usr/local/openresty/nginx/conf/mime.types;
    default_type application/octet-stream;
    server_tokens off;
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 90;
    keepalive_requests 1000;
    reset_timedout_connection on;
    client_max_body_size 0;
    client_body_buffer_size 128k;

    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml application/json application/javascript application/xml image/svg+xml;
    client_body_temp_path %s/client_body;
    proxy_temp_path %s/proxy;
    fastcgi_temp_path %s/fastcgi;
    uwsgi_temp_path %s/uwsgi;
    scgi_temp_path %s/scgi;
    resolver 127.0.0.11 valid=30s ipv6=off;
    resolver_timeout 2s;
    proxy_socket_keepalive on;
    proxy_connect_timeout 5s;
    proxy_cache_path %s levels=1:2 keys_zone=zentproxy_cache:16m max_size=1g inactive=60m use_temp_path=off;

    # Reuse downstream TLS sessions so Cloudflare and browsers do not need a
    # full handshake on every new connection. Certificate selection remains
    # per server_name; this cache only stores negotiated session state.
    ssl_session_cache shared:ZentProxySSL:20m;
    ssl_session_timeout 1h;
    ssl_session_tickets on;
    ssl_buffer_size 4k;
    http2_max_concurrent_streams 256;

    # Client identity is native ngx_http_realip output. A provider-specific
    # header is accepted only when the TCP/transport peer matched that host's
    # configured set_real_ip_from entries. This keeps direct requests from
    # spoofing CF-Connecting-IP/X-Forwarded-For while still supporting Docker
    # Desktop transport hops explicitly trusted for that host.
    map $remote_addr $zp_analytics_ip {
__ZP_ANALYTICS_IP_MAP__    }

    log_format zentproxy_json escape=json '{"ts":"$time_iso8601","host":"$host","ip":"$zp_analytics_ip","method":"$request_method","path":"$uri","query":"","status":$status,"bytes":$body_bytes_sent,"request_time":"$request_time","upstream_time":"$upstream_response_time","user_agent":"$http_user_agent","referer":"$http_referer","http_version":"$server_protocol","tls_version":"$ssl_protocol","upstream_addr":"$upstream_addr"}';
    log_format zentproxy_json_query escape=json '{"ts":"$time_iso8601","host":"$host","ip":"$zp_analytics_ip","method":"$request_method","path":"$uri","query":"$args","status":$status,"bytes":$body_bytes_sent,"request_time":"$request_time","upstream_time":"$upstream_response_time","user_agent":"$http_user_agent","referer":"$http_referer","http_version":"$server_protocol","tls_version":"$ssl_protocol","upstream_addr":"$upstream_addr"}';

    access_log off;

    map $http_upgrade $connection_upgrade {
        default upgrade;
        '' '';
    }

    map $http_x_forwarded_proto $zp_forwarded_proto {
        default $http_x_forwarded_proto;
        '' $scheme;
    }

    map $host $zp_known_host {
        hostnames;
        default 0;
__ZP_KNOWN_HOSTS__    }

    map $host $zp_dead_host {
        hostnames;
        default 0;
__ZP_DEAD_HOSTS__    }

    # Root domains are derived automatically from enabled Proxy Hosts using the
    # same grouping rules as the WebUI. A leading dot matches the root itself
    # and any real subdomain, but never suffix tricks such as example.com.evil.tld.
    map $host $zp_known_root_domain {
        hostnames;
        default 0;
__ZP_ROOT_DOMAINS__    }

`, nginxQuote(nginxErrorLogPath()), pid, capacity.WorkerConnections, nginxQuote(nginxTempDir()), nginxQuote(nginxTempDir()), nginxQuote(nginxTempDir()), nginxQuote(nginxTempDir()), nginxQuote(nginxTempDir()), nginxQuote(proxyCacheDir()))

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
	analyticsMap := "        default $remote_addr;\n"
	switch m.analyticsIPMode {
	case "disabled":
		analyticsMap = "        default \"\";\n"
	case "anonymized":
		analyticsMap = "        default anonymized;\n" +
			"        ~^([0-9][0-9]?[0-9]?)\\.([0-9][0-9]?[0-9]?)\\.([0-9][0-9]?[0-9]?)\\.[0-9][0-9]?[0-9]?$ $1.$2.$3.0;\n" +
			"        ~^([0-9A-Fa-f][0-9A-Fa-f]?[0-9A-Fa-f]?[0-9A-Fa-f]?):([0-9A-Fa-f][0-9A-Fa-f]?[0-9A-Fa-f]?[0-9A-Fa-f]?): $1:$2::;\n"
	}
	confHead := strings.Replace(b.String(), "__ZP_ANALYTICS_IP_MAP__", analyticsMap, 1)
	confHead = strings.Replace(confHead, "__ZP_KNOWN_HOSTS__", knownLines.String(), 1)

	deadDomains := make([]string, 0)
	for _, host := range deadHosts {
		if !host.Enabled {
			continue
		}
		deadDomains = append(deadDomains, host.Domains...)
	}
	sort.Strings(deadDomains)
	var deadLines strings.Builder
	for _, domain := range deadDomains {
		fmt.Fprintf(&deadLines, "        %s 1;\n", domain)
	}
	confHead = strings.Replace(confHead, "__ZP_DEAD_HOSTS__", deadLines.String(), 1)

	var rootLines strings.Builder
	for _, root := range zentLoopRootDomains(hosts) {
		fmt.Fprintf(&rootLines, "        .%s 1;\n", root)
	}
	confHead = strings.Replace(confHead, "__ZP_ROOT_DOMAINS__", rootLines.String(), 1)

	b.Reset()
	b.WriteString(confHead)

	if zentLoop.Enabled {
		for _, h := range hosts {
			if !h.Enabled {
				continue
			}
			routeCIDRs, blockCIDRs, _, _, _, _ := zentLoopRulesForHost(zentLoop, h.ID)
			if len(routeCIDRs) > 0 {
				fmt.Fprintf(&b, "    geo $remote_addr $zp_zentloop_route_%d {\n        default 0;\n", h.ID)
				for _, cidr := range routeCIDRs {
					fmt.Fprintf(&b, "        %s 1;\n", cidr)
				}
				b.WriteString("    }\n\n")
			}
			if len(blockCIDRs) > 0 {
				fmt.Fprintf(&b, "    geo $remote_addr $zp_zentloop_block_%d {\n        default 0;\n", h.ID)
				for _, cidr := range blockCIDRs {
					fmt.Fprintf(&b, "        %s 1;\n", cidr)
				}
				b.WriteString("    }\n\n")
			}
		}
	}

	// Dedicated upstream pools keep backend connections hot. Hostname targets use
	// nginx's runtime resolver, so DNS changes do not require a reload and a
	// temporarily missing backend cannot make the proxy configuration invalid.
	b.WriteString(renderProxyUpstreams(proxyUpstreams, capacity.KeepalivePerUpstream))
	if zentLoop.Enabled {
		fmt.Fprintf(&b, "    upstream zp_zentloop_bridge {\n        server 127.0.0.1:18081;\n        keepalive %d;\n        keepalive_requests 1000;\n        keepalive_timeout 60s;\n    }\n\n", capacity.ZentLoopKeepalive)
	}

	// Unknown host handling is deliberately separate from normal upstream failures.
	fmt.Fprintf(&b, `    server {
        listen 80 default_server backlog=8192;
        server_name _;
        access_log off;
        location ^~ /.well-known/acme-challenge/ { root %s/acme-webroot; try_files $uri =404; access_log off; }
`, data)
	if zentLoop.Enabled {
		if !zentLoop.ForwardUnknownHosts {
			b.WriteString("        if ($zp_known_root_domain = 0) { return 404; }\n")
		}
		fmt.Fprintf(&b, `        location / {
            access_log %s zentproxy_json buffer=256k flush=1s;
            proxy_pass http://zp_zentloop_bridge;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-Host $host;
        }
`, nginxQuote(analyticsLogPath()))
	} else {
		b.WriteString("        location / { return 404; }\n")
	}
	b.WriteString("    }\n\n")

	// HTTPS catch-all uses a local self-signed certificate only to terminate unknown SNI.
	fmt.Fprintf(&b, `    server {
        listen 443 ssl default_server backlog=8192;
        server_name _;
        ssl_certificate %s/certs/default/fullchain.pem;
        ssl_certificate_key %s/certs/default/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        access_log off;
        if ($zp_dead_host = 1) { return 404; }
        if ($zp_known_host = 1) { return 421; }
`, data, data)
	if zentLoop.Enabled {
		if !zentLoop.ForwardUnknownHosts {
			b.WriteString("        if ($zp_known_root_domain = 0) { return 404; }\n")
		}
		fmt.Fprintf(&b, `        location / {
            access_log %s zentproxy_json buffer=256k flush=1s;
            proxy_pass http://zp_zentloop_bridge;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-Host $host;
        }
`, nginxQuote(analyticsLogPath()))
	} else {
		b.WriteString("        location / { return 404; }\n")
	}
	b.WriteString("    }\n\n")

	for _, h := range hosts {
		if !h.Enabled {
			continue
		}
		b.WriteString(renderHost(h, accessLists, providers, certificateMap, zentLoop, m.dataDir, trustedTransportHops))
	}
	for _, h := range redirects {
		if !h.Enabled {
			continue
		}
		b.WriteString(renderRedirectHost(h, providers, certificateMap, m.dataDir, trustedTransportHops))
	}
	for _, h := range deadHosts {
		if !h.Enabled {
			continue
		}
		b.WriteString(renderDeadHost(h, providers, certificateMap, m.dataDir, trustedTransportHops))
	}
	b.WriteString("}\n")
	if len(streams) > 0 {
		b.WriteString(renderStreams(streams, certificateMap))
	}
	return b.Bytes(), nil
}

func NormalizeStoredHost(h model.Host) (model.Host, error) {
	in, err := NormalizeAndValidate(model.HostInput{Name: h.Name, Domains: h.Domains, Scheme: h.Scheme, ForwardHost: h.ForwardHost, ForwardPort: h.ForwardPort, Enabled: h.Enabled, WebSockets: h.WebSockets, PreserveHost: h.PreserveHost, StatisticsEnabled: h.StatisticsEnabled, StoreQueryString: h.StoreQueryString, TrustedProxyProviderID: h.TrustedProxyProviderID, AccessListID: h.AccessListID, BlockCommonExploits: h.BlockCommonExploits, CertificateID: h.CertificateID, SSLForced: h.SSLForced, HTTP2Support: h.HTTP2Support, HSTSEnabled: h.HSTSEnabled, HSTSSubdomains: h.HSTSSubdomains, CachingEnabled: h.CachingEnabled, TrustForwardedProto: h.TrustForwardedProto, AdvancedConfig: h.AdvancedConfig, CustomLocations: h.CustomLocations})
	if err != nil {
		return h, err
	}
	h.Name, h.Domains, h.Scheme, h.ForwardHost, h.ForwardPort = in.Name, in.Domains, in.Scheme, in.ForwardHost, in.ForwardPort
	h.CustomLocations = in.CustomLocations
	return h, nil
}

func ValidateStoredHost(h model.Host) error {
	_, err := NormalizeStoredHost(h)
	return err
}

type proxyUpstream struct {
	Name          string
	Host          string
	Port          int
	Scheme        string
	KeepaliveSafe bool
}

func upstreamPoolIdentity(h model.Host, scheme, host string, port int) (string, bool) {
	scheme = strings.ToLower(strings.TrimSpace(scheme))
	host = strings.ToLower(strings.TrimSpace(host))
	base := fmt.Sprintf("%s|%s|%d", scheme, host, port)
	// HTTPS to an IP while Preserve Host is enabled derives SNI from $host.
	// A keepalive connection established for one frontend hostname must never be
	// reused for another hostname/SNI, so keep this case host-local and disable
	// idle connection reuse for the pool. Static backend SNI/HTTP pools are safe
	// to share across Proxy Hosts that target the exact same backend.
	if scheme == "https" && net.ParseIP(strings.Trim(host, "[]")) != nil && h.PreserveHost {
		return fmt.Sprintf("%s|dynamic-sni|host:%d", base, h.ID), false
	}
	return base, true
}

func upstreamName(h model.Host, scheme, host string, port int) string {
	identity, _ := upstreamPoolIdentity(h, scheme, host, port)
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(identity))
	return fmt.Sprintf("zp_u_%08x", hash.Sum32())
}

func effectiveLocationTarget(h model.Host, loc model.CustomLocation) (scheme, host string, port int) {
	scheme = strings.ToLower(strings.TrimSpace(loc.Scheme))
	if scheme != "https" {
		scheme = "http"
	}
	host = strings.TrimSpace(loc.ForwardHost)
	if host == "" {
		host = strings.TrimSpace(h.ForwardHost)
	}
	port = loc.ForwardPort
	if port < 1 {
		port = h.ForwardPort
	}
	return scheme, host, port
}

func collectProxyUpstreams(hosts []model.Host) []proxyUpstream {
	seen := map[string]proxyUpstream{}
	for _, h := range hosts {
		if !h.Enabled {
			continue
		}
		locations := append([]model.CustomLocation(nil), h.CustomLocations...)
		locations = append(locations, model.CustomLocation{Path: "/", Scheme: h.Scheme, ForwardHost: h.ForwardHost, ForwardPort: h.ForwardPort})
		for _, loc := range locations {
			scheme, host, port := effectiveLocationTarget(h, loc)
			if host == "" || port < 1 {
				continue
			}
			identity, keepaliveSafe := upstreamPoolIdentity(h, scheme, host, port)
			name := upstreamName(h, scheme, host, port)
			seen[identity] = proxyUpstream{Name: name, Host: host, Port: port, Scheme: scheme, KeepaliveSafe: keepaliveSafe}
		}
	}
	out := make([]proxyUpstream, 0, len(seen))
	for _, upstream := range seen {
		out = append(out, upstream)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func renderProxyUpstreams(upstreams []proxyUpstream, keepalive int) string {
	var b strings.Builder
	for _, upstream := range upstreams {
		host := strings.TrimSpace(upstream.Host)
		serverHost := host
		if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
			if strings.Contains(ip.String(), ":") {
				serverHost = "[" + ip.String() + "]"
			} else {
				serverHost = ip.String()
			}
		}
		fmt.Fprintf(&b, "    upstream %s {\n        zone %s 64k;\n", upstream.Name, upstream.Name)
		if net.ParseIP(strings.Trim(host, "[]")) == nil {
			fmt.Fprintf(&b, "        server %s:%d resolve;\n", serverHost, upstream.Port)
		} else {
			fmt.Fprintf(&b, "        server %s:%d;\n", serverHost, upstream.Port)
		}
		if upstream.KeepaliveSafe && keepalive > 0 {
			fmt.Fprintf(&b, "        keepalive %d;\n        keepalive_requests 1000;\n        keepalive_timeout 60s;\n", keepalive)
		}
		b.WriteString("    }\n\n")
	}
	return b.String()
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
		fmt.Fprintf(&b, "        access_log %s %s buffer=256k flush=1s;\n", nginxQuote(analyticsLogPath()), format)
	} else {
		b.WriteString("        access_log off;\n")
	}
	b.WriteString("        location ^~ /.well-known/acme-challenge/ { root " + nginxQuote(dataDir) + "/acme-webroot; try_files $uri =404; access_log off; }\n")
	if !tlsEnabled && h.SSLForced && cert != nil {
		b.WriteString("        location / { return 301 https://$host$request_uri; }\n    }\n\n")
		return b.String()
	}
	// A container runtime may SNAT published-port traffic before OpenResty.
	// Managed trusted-proxy directives are emitted only when this host explicitly
	// selects a provider.
	b.WriteString(renderTrustedProxyDirectives(h.TrustedProxyProviderID, providers, trustedTransportHops, "        "))
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
			b.WriteString("        location @zentproxy_zentloop {\n            proxy_pass http://zp_zentloop_bridge;\n            proxy_http_version 1.1;\n            proxy_set_header Host $host;\n            proxy_set_header X-Real-IP $remote_addr;\n            proxy_set_header X-Forwarded-For $remote_addr;\n            proxy_set_header X-Forwarded-Proto $scheme;\n            proxy_set_header X-Forwarded-Host $host;\n            proxy_set_header X-ZentLoop-Catch-All 0;\n        }\n")
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
			hasAllow := false
			hasDenyAll := false
			for _, rule := range a.Rules {
				directive := strings.ToLower(strings.TrimSpace(rule.Directive))
				address := strings.TrimSpace(rule.Address)
				if (directive == "allow" || directive == "deny") && validAccessAddress(address) {
					fmt.Fprintf(&b, "        %s %s;\n", directive, address)
					if directive == "allow" {
						hasAllow = true
					}
					if directive == "deny" && strings.EqualFold(address, "all") {
						hasDenyAll = true
					}
				}
			}
			// An allow list is a whitelist. Without a terminal deny, nginx's
			// access module allows addresses that did not match any rule.
			if hasAllow && !hasDenyAll {
				b.WriteString("        deny all;\n")
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

func proxyUpstreamHostHeader(host string, port int) string {
	host = strings.TrimSpace(host)
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		if strings.Contains(ip.String(), ":") {
			host = "[" + ip.String() + "]"
		} else {
			host = ip.String()
		}
	}
	return host + ":" + strconv.Itoa(port)
}

func renderLocation(h model.Host, loc model.CustomLocation, indent string) string {
	path := strings.TrimSpace(loc.Path)
	if path == "" {
		path = "/"
	}
	if strings.ContainsAny(path, "\r\n{};") {
		return ""
	}
	scheme, host, port := effectiveLocationTarget(h, loc)
	forwardPath := strings.TrimSpace(loc.ForwardPath)
	if forwardPath != "" && !strings.HasPrefix(forwardPath, "/") {
		forwardPath = "/" + forwardPath
	}
	pool := upstreamName(h, scheme, host, port)
	upstream := scheme + "://" + pool + forwardPath
	var b strings.Builder
	fmt.Fprintf(&b, "%slocation %s {\n", indent, path)
	fmt.Fprintf(&b, "%s    proxy_pass %s;\n", indent, upstream)
	fmt.Fprintf(&b, "%s    proxy_http_version 1.1;\n", indent)
	if h.PreserveHost {
		fmt.Fprintf(&b, "%s    proxy_set_header Host $host;\n", indent)
	} else {
		fmt.Fprintf(&b, "%s    proxy_set_header Host %s;\n", indent, proxyUpstreamHostHeader(host, port))
	}
	fmt.Fprintf(&b, "%s    proxy_set_header X-Real-IP $remote_addr;\n%s    proxy_set_header X-Forwarded-For $remote_addr;\n", indent, indent)
	if h.TrustForwardedProto {
		fmt.Fprintf(&b, "%s    proxy_set_header X-Forwarded-Proto $zp_forwarded_proto;\n", indent)
	} else {
		fmt.Fprintf(&b, "%s    proxy_set_header X-Forwarded-Proto $scheme;\n", indent)
	}
	fmt.Fprintf(&b, "%s    proxy_set_header X-Forwarded-Host $host;\n", indent)
	if h.WebSockets {
		fmt.Fprintf(&b, "%s    proxy_set_header Upgrade $http_upgrade;\n%s    proxy_set_header Connection $connection_upgrade;\n", indent, indent)
		fmt.Fprintf(&b, "%s    proxy_read_timeout 3600s;\n%s    proxy_send_timeout 3600s;\n", indent, indent)
	} else {
		// nginx otherwise sends "Connection: close" to HTTP upstreams, which
		// prevents the upstream keepalive pool from being reused.
		fmt.Fprintf(&b, "%s    proxy_set_header Connection \"\";\n", indent)
	}
	if scheme == "https" {
		// Upstream TLS must send a meaningful SNI name. Hostname targets use the
		// configured backend name. For an IP target with Preserve Host enabled,
		// the already validated request host is the best SNI identity. That value
		// can vary per request, so both idle connection reuse and TLS session reuse
		// are disabled for this special case to prevent cross-host SNI reuse.
		if net.ParseIP(strings.Trim(host, "[]")) == nil {
			fmt.Fprintf(&b, "%s    proxy_ssl_server_name on;\n%s    proxy_ssl_name %s;\n", indent, indent, host)
			fmt.Fprintf(&b, "%s    proxy_ssl_session_reuse on;\n", indent)
		} else if h.PreserveHost {
			fmt.Fprintf(&b, "%s    proxy_ssl_server_name on;\n%s    proxy_ssl_name $host;\n", indent, indent)
			fmt.Fprintf(&b, "%s    proxy_ssl_session_reuse off;\n", indent)
		} else {
			fmt.Fprintf(&b, "%s    proxy_ssl_server_name off;\n", indent)
			fmt.Fprintf(&b, "%s    proxy_ssl_session_reuse on;\n", indent)
		}
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

func renderTrustedProxyDirectives(providerID *int64, providers map[int64]model.TrustedProxyProvider, trustedTransportHops []string, indent string) string {
	if providerID == nil {
		return ""
	}
	p, ok := providers[*providerID]
	if !ok {
		return ""
	}
	var b strings.Builder
	for _, cidr := range p.CIDRs {
		fmt.Fprintf(&b, "%sset_real_ip_from %s;\n", indent, cidr)
	}
	for _, cidr := range trustedTransportHops {
		fmt.Fprintf(&b, "%sset_real_ip_from %s;\n", indent, cidr)
	}
	if p.Header != "" {
		fmt.Fprintf(&b, "%sreal_ip_header %s;\n%sreal_ip_recursive on;\n", indent, p.Header, indent)
	}
	return b.String()
}

func renderRedirectHost(h model.RedirectHost, providers map[int64]model.TrustedProxyProvider, certificates map[int64]model.Certificate, dataDir string, trustedTransportHops []string) string {
	var cert *model.Certificate
	if h.CertificateID != nil {
		if c, ok := certificates[*h.CertificateID]; ok {
			cert = &c
		}
	}
	var b strings.Builder
	b.WriteString(renderRedirectServer(h, providers, dataDir, false, cert, trustedTransportHops))
	if cert != nil && cert.CertPath != "" && cert.KeyPath != "" {
		b.WriteString(renderRedirectServer(h, providers, dataDir, true, cert, trustedTransportHops))
	}
	return b.String()
}

func renderRedirectServer(h model.RedirectHost, providers map[int64]model.TrustedProxyProvider, dataDir string, tlsEnabled bool, cert *model.Certificate, trustedTransportHops []string) string {
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
	b.WriteString(renderTrustedProxyDirectives(h.TrustedProxyProviderID, providers, trustedTransportHops, "        "))
	if !tlsEnabled && h.SSLForced && cert != nil {
		b.WriteString("        location / { return 301 https://$host$request_uri; }\n    }\n\n")
		return b.String()
	}
	if h.BlockExploits {
		b.WriteString("        location ~* ^/(?:\\.git|\\.svn|\\.hg)(?:/|$) { return 404; }\n")
	}
	advancedConfig := h.AdvancedConfig
	if h.TrustedProxyProviderID != nil {
		advancedConfig = stripManagedRealIPDirectives(advancedConfig)
	}
	if strings.TrimSpace(advancedConfig) != "" {
		b.WriteString(indentConfig(advancedConfig, "        "))
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

func renderDeadHost(h model.DeadHost, providers map[int64]model.TrustedProxyProvider, certificates map[int64]model.Certificate, dataDir string, trustedTransportHops []string) string {
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
		b.WriteString(renderTrustedProxyDirectives(h.TrustedProxyProviderID, providers, trustedTransportHops, "        "))
		if !tlsEnabled && h.SSLForced && cert != nil {
			b.WriteString("        location / { return 301 https://$host$request_uri; }\n    }\n\n")
			continue
		}
		advancedConfig := h.AdvancedConfig
		if h.TrustedProxyProviderID != nil {
			advancedConfig = stripManagedRealIPDirectives(advancedConfig)
		}
		if strings.TrimSpace(advancedConfig) != "" {
			b.WriteString(indentConfig(advancedConfig, "        "))
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
