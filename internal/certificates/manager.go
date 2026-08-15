package certificates

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zentproxy/zentproxy/internal/db"
	"github.com/zentproxy/zentproxy/internal/model"
)

var envNameRE = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

type Manager struct {
	store   *db.Store
	dataDir string
	apply   func() error
	mu      sync.Mutex
}

func New(store *db.Store, dataDir string, apply func() error) *Manager {
	return &Manager{store: store, dataDir: dataDir, apply: apply}
}

func (m *Manager) Start(ctx context.Context) {
	go func() {
		timer := time.NewTimer(2 * time.Minute)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			_ = m.RenewDue(ctx)
		}
		ticker := time.NewTicker(12 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = m.RenewDue(ctx)
			}
		}
	}()
}

func NormalizeDomains(in []string) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		d := strings.ToLower(strings.TrimSpace(raw))
		if d == "" {
			continue
		}
		if strings.ContainsAny(d, " \t\r\n/;{}") {
			return nil, fmt.Errorf("invalid certificate name: %s", d)
		}
		if strings.HasPrefix(d, "*.") {
			if net.ParseIP(strings.TrimPrefix(d, "*.")) != nil {
				return nil, fmt.Errorf("wildcard cannot target an IP address: %s", d)
			}
		}
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	if len(out) == 0 || len(out) > 100 {
		return nil, errors.New("at least one and at most 100 certificate names are required")
	}
	sort.Strings(out)
	return out, nil
}

func (m *Manager) Issue(ctx context.Context, in model.CertificateInput) (model.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	domains, err := NormalizeDomains(in.Domains)
	if err != nil {
		return model.Certificate{}, err
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		in.Name = domains[0]
	}
	in.Challenge = strings.ToLower(strings.TrimSpace(in.Challenge))
	if in.Challenge == "" {
		in.Challenge = "http-01"
	}
	if in.Challenge != "http-01" && in.Challenge != "dns-01" {
		return model.Certificate{}, errors.New("challenge must be http-01 or dns-01")
	}
	in.Email = strings.TrimSpace(in.Email)
	if _, err := mail.ParseAddress(in.Email); err != nil {
		return model.Certificate{}, errors.New("a valid Let's Encrypt account email is required")
	}
	if in.Challenge == "dns-01" && strings.TrimSpace(in.DNSProvider) == "" {
		return model.Certificate{}, errors.New("dns_provider is required for DNS-01")
	}
	if in.Challenge == "http-01" {
		for _, d := range domains {
			if strings.HasPrefix(d, "*.") {
				return model.Certificate{}, errors.New("wildcard certificates require DNS-01")
			}
		}
	}
	c, err := m.store.CreateCertificate(model.Certificate{Name: in.Name, Provider: "letsencrypt", Domains: domains, Challenge: in.Challenge, Email: in.Email, DNSProvider: strings.TrimSpace(in.DNSProvider), AutoRenew: in.AutoRenew})
	if err != nil {
		return model.Certificate{}, err
	}
	if err := m.preparePaths(&c, in.DNSCredentials); err != nil {
		_ = m.store.DeleteCertificate(c.ID)
		return model.Certificate{}, err
	}
	if _, err = m.store.UpdateCertificate(c); err != nil {
		_ = m.store.DeleteCertificate(c.ID)
		return model.Certificate{}, err
	}
	if err := m.runLego(ctx, c); err != nil {
		c.LastError = err.Error()
		_, _ = m.store.UpdateCertificate(c)
		return c, err
	}
	c, err = m.refreshMetadata(c)
	if err != nil {
		return c, err
	}
	c.LastError = ""
	c.LastRenewed = ptrTime(time.Now().UTC())
	c, err = m.store.UpdateCertificate(c)
	if err == nil && m.apply != nil {
		err = m.apply()
	}
	return c, err
}

func (m *Manager) Import(in model.CertificateImportInput) (model.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	domains, err := NormalizeDomains(in.Domains)
	if err != nil {
		return model.Certificate{}, err
	}
	if _, err := tls.X509KeyPair([]byte(in.CertificatePEM), []byte(in.PrivateKeyPEM)); err != nil {
		return model.Certificate{}, fmt.Errorf("certificate/private key mismatch: %w", err)
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		in.Name = domains[0]
	}
	provider := strings.TrimSpace(in.Provider)
	if provider == "" {
		provider = "custom"
	}
	challenge := strings.TrimSpace(in.Challenge)
	if challenge == "" {
		challenge = "imported"
	}
	c, err := m.store.CreateCertificate(model.Certificate{Name: in.Name, Provider: provider, Domains: domains, Challenge: challenge, Email: strings.TrimSpace(in.Email), DNSProvider: strings.TrimSpace(in.DNSProvider), AutoRenew: in.AutoRenew})
	if err != nil {
		return model.Certificate{}, err
	}
	certDir := filepath.Join(m.dataDir, "certs", strconv.FormatInt(c.ID, 10))
	if err := os.MkdirAll(certDir, 0o750); err != nil {
		_ = m.store.DeleteCertificate(c.ID)
		return model.Certificate{}, err
	}
	c.CertPath = filepath.Join(certDir, "fullchain.pem")
	c.KeyPath = filepath.Join(certDir, "privkey.pem")
	if err := os.WriteFile(c.CertPath, []byte(in.CertificatePEM), 0o640); err != nil {
		_ = m.store.DeleteCertificate(c.ID)
		return model.Certificate{}, err
	}
	if err := os.WriteFile(c.KeyPath, []byte(in.PrivateKeyPEM), 0o600); err != nil {
		_ = m.store.DeleteCertificate(c.ID)
		return model.Certificate{}, err
	}
	if err := m.writeDNSEnv(c.ID, in.DNSCredentials); err != nil {
		_ = m.store.DeleteCertificate(c.ID)
		return model.Certificate{}, err
	}
	c, err = m.refreshMetadata(c)
	if err != nil {
		_ = m.store.DeleteCertificate(c.ID)
		return model.Certificate{}, err
	}
	c.LastRenewed = ptrTime(time.Now().UTC())
	c.LastError = ""
	c, err = m.store.UpdateCertificate(c)
	if err == nil && m.apply != nil {
		err = m.apply()
	}
	return c, err
}

func (m *Manager) preparePaths(c *model.Certificate, creds map[string]string) error {
	certDir := filepath.Join(m.dataDir, "certs", strconv.FormatInt(c.ID, 10))
	if err := os.MkdirAll(certDir, 0o750); err != nil {
		return err
	}
	c.CertPath = filepath.Join(certDir, "fullchain.pem")
	c.KeyPath = filepath.Join(certDir, "privkey.pem")
	return m.writeDNSEnv(c.ID, creds)
}

func (m *Manager) writeDNSEnv(id int64, creds map[string]string) error {
	if len(creds) == 0 {
		return nil
	}
	dir := filepath.Join(m.dataDir, "certs", strconv.FormatInt(id, 10))
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	keys := make([]string, 0, len(creds))
	for k := range creds {
		if !envNameRE.MatchString(k) {
			return fmt.Errorf("invalid DNS credential variable: %s", k)
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		v := creds[k]
		if strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf("DNS credential %s contains a newline", k)
		}
		fmt.Fprintf(&b, "%s=%s\n", k, strconv.Quote(v))
	}
	return os.WriteFile(filepath.Join(dir, "dns.env"), []byte(b.String()), 0o600)
}

func (m *Manager) runLego(ctx context.Context, c model.Certificate) error {
	binary := "/usr/local/bin/lego"
	if _, err := os.Stat(binary); err != nil {
		return errors.New("ACME client is not installed in this image")
	}
	acmePath := filepath.Join(m.dataDir, "acme")
	if err := os.MkdirAll(filepath.Join(m.dataDir, "acme-webroot", ".well-known", "acme-challenge"), 0o750); err != nil {
		return err
	}
	args := []string{"run", "--path", acmePath, "--accept-tos", "--server", "letsencrypt", "--email", c.Email, "--cert.name", fmt.Sprintf("zentproxy-%d", c.ID), "--key-type", "EC256"}
	hasIP := false
	for _, d := range c.Domains {
		args = append(args, "--domains", d)
		if net.ParseIP(strings.Trim(d, "[]")) != nil {
			hasIP = true
		}
	}
	if hasIP {
		args = append(args, "--profile", "shortlived")
	}
	if c.Challenge == "dns-01" {
		args = append(args, "--dns", c.DNSProvider)
		envPath := filepath.Join(m.dataDir, "certs", strconv.FormatInt(c.ID, 10), "dns.env")
		if st, err := os.Stat(envPath); err == nil && st.Size() > 0 {
			args = append(args, "--env-file", envPath)
		}
	} else {
		args = append(args, "--http", "--http.webroot", filepath.Join(m.dataDir, "acme-webroot"))
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("Let's Encrypt failed: %v: %s", err, trimOutput(out))
	}
	srcBase := filepath.Join(acmePath, "certificates", fmt.Sprintf("zentproxy-%d", c.ID))
	if err := copyFile(srcBase+".crt", c.CertPath, 0o640); err != nil {
		return err
	}
	if err := copyFile(srcBase+".key", c.KeyPath, 0o600); err != nil {
		return err
	}
	return nil
}

func (m *Manager) Renew(ctx context.Context, id int64, force bool) (model.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, err := m.store.GetCertificate(id)
	if err != nil {
		return c, err
	}
	if c.Provider != "letsencrypt" && c.Provider != "imported-letsencrypt" {
		return c, errors.New("certificate is not managed by Let's Encrypt")
	}
	if !force && !shouldRenew(c.CertPath) {
		return c, nil
	}
	if err := m.runLego(ctx, c); err != nil {
		c.LastError = err.Error()
		_, _ = m.store.UpdateCertificate(c)
		return c, err
	}
	c, err = m.refreshMetadata(c)
	if err != nil {
		return c, err
	}
	c.Provider = "letsencrypt"
	c.LastError = ""
	c.LastRenewed = ptrTime(time.Now().UTC())
	c, err = m.store.UpdateCertificate(c)
	if err == nil && m.apply != nil {
		err = m.apply()
	}
	return c, err
}
func (m *Manager) RenewDue(ctx context.Context) error {
	certs, err := m.store.ListCertificates()
	if err != nil {
		return err
	}
	for _, c := range certs {
		if c.AutoRenew && (c.Provider == "letsencrypt" || c.Provider == "imported-letsencrypt") && shouldRenew(c.CertPath) {
			_, _ = m.Renew(ctx, c.ID, false)
		}
	}
	return nil
}

// List returns certificate metadata and opportunistically repairs metadata from
// the authoritative X.509 certificate on disk. This keeps migrated/legacy rows
// from leaking malformed domain metadata into the API/UI.
func (m *Manager) List() ([]model.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	certs, err := m.store.ListCertificates()
	if err != nil {
		return nil, err
	}
	for i := range certs {
		if strings.TrimSpace(certs[i].CertPath) == "" {
			continue
		}
		refreshed, err := m.refreshMetadata(certs[i])
		if err != nil {
			continue
		}
		if !stringSlicesEqual(certs[i].Domains, refreshed.Domains) || !timesEqual(certs[i].ExpiresAt, refreshed.ExpiresAt) {
			if saved, err := m.store.UpdateCertificate(refreshed); err == nil {
				refreshed = saved
			}
		}
		certs[i] = refreshed
	}
	return certs, nil
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func timesEqual(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(*b)
}

func (m *Manager) refreshMetadata(c model.Certificate) (model.Certificate, error) {
	cert, err := readLeaf(c.CertPath)
	if err != nil {
		return c, err
	}
	t := cert.NotAfter.UTC()
	c.ExpiresAt = &t
	names := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses)+1)
	names = append(names, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		names = append(names, ip.String())
	}
	if len(names) == 0 && strings.TrimSpace(cert.Subject.CommonName) != "" {
		names = append(names, cert.Subject.CommonName)
	}
	if normalized, err := NormalizeDomains(names); err == nil && len(normalized) > 0 {
		c.Domains = normalized
	}
	return c, nil
}
func shouldRenew(path string) bool {
	cert, err := readLeaf(path)
	if err != nil {
		return true
	}
	life := cert.NotAfter.Sub(cert.NotBefore)
	if life <= 0 {
		return true
	}
	return time.Now().UTC().After(cert.NotBefore.Add(life * 2 / 3))
}
func readLeaf(path string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("certificate PEM is invalid")
	}
	return x509.ParseCertificate(block.Bytes)
}
func copyFile(src, dst string, mode os.FileMode) error {
	raw, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read ACME output: %w", err)
	}
	return os.WriteFile(dst, raw, mode)
}
func trimOutput(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 1200 {
		s = s[len(s)-1200:]
	}
	return s
}
func ptrTime(t time.Time) *time.Time { return &t }

// Delete removes certificate metadata and local private material. Callers must
// ensure no routing object references the certificate before invoking it.
func (m *Manager) Delete(id int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id < 1 {
		return sql.ErrNoRows
	}
	if _, err := m.store.GetCertificate(id); err != nil {
		return err
	}
	if err := m.store.DeleteCertificate(id); err != nil {
		return err
	}
	_ = os.RemoveAll(filepath.Join(m.dataDir, "certs", strconv.FormatInt(id, 10)))
	acmeBase := filepath.Join(m.dataDir, "acme", "certificates", fmt.Sprintf("zentproxy-%d", id))
	for _, suffix := range []string{".crt", ".key", ".issuer.crt", ".json"} {
		_ = os.Remove(acmeBase + suffix)
	}
	return nil
}
