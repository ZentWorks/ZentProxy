package migration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zentproxy/zentproxy/internal/model"
	"github.com/zentproxy/zentproxy/internal/proxy"
)

const maxResponseBytes = 16 << 20

type Credentials struct {
	BaseURL       string `json:"base_url"`
	Identity      string `json:"identity"`
	Secret        string `json:"secret"`
	TLSSkipVerify bool   `json:"tls_skip_verify"`
}

type SourceInfo struct {
	URL     string `json:"url"`
	Version string `json:"version,omitempty"`
}

type ResourceCount struct {
	Key        string `json:"key"`
	Label      string `json:"label"`
	Count      int    `json:"count"`
	Importable bool   `json:"importable"`
	Note       string `json:"note,omitempty"`
}

type ProxyHostPlan struct {
	SourceID            int64           `json:"source_id"`
	SourceCertificateID int64           `json:"source_certificate_id,omitempty"`
	SourceAccessListID  int64           `json:"source_access_list_id,omitempty"`
	Name                string          `json:"name"`
	Domains             []string        `json:"domains"`
	Upstream            string          `json:"upstream"`
	Enabled             bool            `json:"enabled"`
	Importable          bool            `json:"importable"`
	Conflict            string          `json:"conflict,omitempty"`
	Warnings            []string        `json:"warnings"`
	Input               model.HostInput `json:"-"`
}

type CertificatePlan struct {
	SourceID       int64                        `json:"source_id"`
	Name           string                       `json:"name"`
	Provider       string                       `json:"provider"`
	Domains        []string                     `json:"domains"`
	ExpiresOn      string                       `json:"expires_on,omitempty"`
	Importable     bool                         `json:"importable"`
	MaterialSource string                       `json:"material_source,omitempty"`
	Reissue        bool                         `json:"reissue,omitempty"`
	Warning        string                       `json:"warning,omitempty"`
	Input          model.CertificateImportInput `json:"-"`
}

type AccessListPlan struct {
	SourceID   int64                 `json:"source_id"`
	Name       string                `json:"name"`
	Importable bool                  `json:"importable"`
	Warning    string                `json:"warning,omitempty"`
	AuthSource string                `json:"auth_source,omitempty"`
	Input      model.AccessListInput `json:"-"`
}

type RedirectHostPlan struct {
	SourceID            int64                   `json:"source_id"`
	SourceCertificateID int64                   `json:"source_certificate_id,omitempty"`
	Domains             []string                `json:"domains"`
	Importable          bool                    `json:"importable"`
	Warning             string                  `json:"warning,omitempty"`
	Input               model.RedirectHostInput `json:"-"`
}

type DeadHostPlan struct {
	SourceID            int64               `json:"source_id"`
	SourceCertificateID int64               `json:"source_certificate_id,omitempty"`
	Domains             []string            `json:"domains"`
	Importable          bool                `json:"importable"`
	Warning             string              `json:"warning,omitempty"`
	Input               model.DeadHostInput `json:"-"`
}

type StreamPlan struct {
	SourceID            int64             `json:"source_id"`
	SourceCertificateID int64             `json:"source_certificate_id,omitempty"`
	IncomingPort        int               `json:"incoming_port"`
	Importable          bool              `json:"importable"`
	Warning             string            `json:"warning,omitempty"`
	Input               model.StreamInput `json:"-"`
}

type Batch struct {
	Hosts        []ProxyHostPlan    `json:"-"`
	Certificates []CertificatePlan  `json:"-"`
	AccessLists  []AccessListPlan   `json:"-"`
	Redirects    []RedirectHostPlan `json:"-"`
	DeadHosts    []DeadHostPlan     `json:"-"`
	Streams      []StreamPlan       `json:"-"`
	Warnings     []string           `json:"-"`
}

type Analysis struct {
	Source       SourceInfo         `json:"source"`
	Resources    []ResourceCount    `json:"resources"`
	ProxyHosts   []ProxyHostPlan    `json:"proxy_hosts"`
	Certificates []CertificatePlan  `json:"certificates"`
	AccessLists  []AccessListPlan   `json:"access_lists"`
	Redirects    []RedirectHostPlan `json:"redirect_hosts"`
	DeadHosts    []DeadHostPlan     `json:"dead_hosts"`
	Streams      []StreamPlan       `json:"streams"`
	Importable   int                `json:"importable_proxy_hosts"`
	Blocked      int                `json:"blocked_proxy_hosts"`
	GeneralNotes []string           `json:"general_notes"`
}

type ImportResult struct {
	Imported             int      `json:"imported"`
	ImportedCertificates int      `json:"imported_certificates"`
	ImportedAccessLists  int      `json:"imported_access_lists"`
	ImportedRedirects    int      `json:"imported_redirect_hosts"`
	ImportedDeadHosts    int      `json:"imported_dead_hosts"`
	ImportedStreams      int      `json:"imported_streams"`
	Skipped              int      `json:"skipped"`
	HostIDs              []int64  `json:"host_ids"`
	CertificateIDs       []int64  `json:"certificate_ids"`
	AccessListIDs        []int64  `json:"access_list_ids"`
	RedirectIDs          []int64  `json:"redirect_ids"`
	DeadHostIDs          []int64  `json:"dead_host_ids"`
	StreamIDs            []int64  `json:"stream_ids"`
	Warnings             []string `json:"warnings"`
	FailedCertificates   int      `json:"failed_certificates"`
	CertificateErrors    []string `json:"certificate_errors"`
}

type npmProxyHost struct {
	ID                    int64         `json:"id"`
	DomainNames           []string      `json:"domain_names"`
	ForwardHost           string        `json:"forward_host"`
	ForwardPort           int           `json:"forward_port"`
	ForwardScheme         string        `json:"forward_scheme"`
	Enabled               intBool       `json:"enabled"`
	AllowWebsocketUpgrade intBool       `json:"allow_websocket_upgrade"`
	BlockExploits         intBool       `json:"block_exploits"`
	CachingEnabled        intBool       `json:"caching_enabled"`
	HTTP2Support          intBool       `json:"http2_support"`
	SSLForced             intBool       `json:"ssl_forced"`
	HSTSEnabled           intBool       `json:"hsts_enabled"`
	HSTSSubdomains        intBool       `json:"hsts_subdomains"`
	TrustForwardedProto   intBool       `json:"trust_forwarded_proto"`
	AccessListID          int64         `json:"access_list_id"`
	CertificateID         int64         `json:"certificate_id"`
	AdvancedConfig        string        `json:"advanced_config"`
	Locations             []npmLocation `json:"locations"`
}

type npmCertificate struct {
	ID          int64              `json:"id"`
	Provider    string             `json:"provider"`
	NiceName    string             `json:"nice_name"`
	DomainNames []string           `json:"domain_names"`
	ExpiresOn   string             `json:"expires_on"`
	Meta        npmCertificateMeta `json:"meta"`
}
type npmCertificateMeta struct {
	Certificate            string  `json:"certificate"`
	CertificateKey         string  `json:"certificate_key"`
	DNSChallenge           intBool `json:"dns_challenge"`
	DNSProviderCredentials string  `json:"dns_provider_credentials"`
	DNSProvider            string  `json:"dns_provider"`
	LetsEncryptEmail       string  `json:"letsencrypt_email"`
	PropagationSeconds     int     `json:"propagation_seconds"`
	KeyType                string  `json:"key_type"`
}

type npmAccessList struct {
	ID         int64             `json:"id"`
	Name       string            `json:"name"`
	SatisfyAny intBool           `json:"satisfy_any"`
	PassAuth   intBool           `json:"pass_auth"`
	Items      []npmAccessItem   `json:"items"`
	Clients    []npmAccessClient `json:"clients"`
}
type npmAccessItem struct {
	Username string `json:"username"`
	Password string `json:"password"`
}
type npmAccessClient struct {
	Address   string `json:"address"`
	Directive string `json:"directive"`
}
type npmRedirectHost struct {
	ID                int64    `json:"id"`
	DomainNames       []string `json:"domain_names"`
	ForwardHTTPCode   int      `json:"forward_http_code"`
	ForwardScheme     string   `json:"forward_scheme"`
	ForwardDomainName string   `json:"forward_domain_name"`
	PreservePath      intBool  `json:"preserve_path"`
	CertificateID     int64    `json:"certificate_id"`
	SSLForced         intBool  `json:"ssl_forced"`
	HTTP2Support      intBool  `json:"http2_support"`
	HSTSEnabled       intBool  `json:"hsts_enabled"`
	HSTSSubdomains    intBool  `json:"hsts_subdomains"`
	BlockExploits     intBool  `json:"block_exploits"`
	AdvancedConfig    string   `json:"advanced_config"`
	Enabled           intBool  `json:"enabled"`
}
type npmDeadHost struct {
	ID             int64    `json:"id"`
	DomainNames    []string `json:"domain_names"`
	CertificateID  int64    `json:"certificate_id"`
	SSLForced      intBool  `json:"ssl_forced"`
	HTTP2Support   intBool  `json:"http2_support"`
	HSTSEnabled    intBool  `json:"hsts_enabled"`
	HSTSSubdomains intBool  `json:"hsts_subdomains"`
	AdvancedConfig string   `json:"advanced_config"`
	Enabled        intBool  `json:"enabled"`
}
type npmStream struct {
	ID            int64   `json:"id"`
	IncomingPort  int     `json:"incoming_port"`
	ForwardHost   string  `json:"forwarding_host"`
	ForwardPort   int     `json:"forwarding_port"`
	TCPForwarding intBool `json:"tcp_forwarding"`
	UDPForwarding intBool `json:"udp_forwarding"`
	CertificateID int64   `json:"certificate_id"`
	Enabled       intBool `json:"enabled"`
}

type npmLocation struct {
	Path           string `json:"path"`
	ForwardScheme  string `json:"forward_scheme"`
	ForwardHost    string `json:"forward_host"`
	ForwardPort    int    `json:"forward_port"`
	ForwardPath    string `json:"forward_path"`
	AdvancedConfig string `json:"advanced_config"`
}

type intBool bool

func (b *intBool) UnmarshalJSON(raw []byte) error {
	s := strings.TrimSpace(string(raw))
	switch s {
	case "true", "1", `"1"`:
		*b = true
		return nil
	case "false", "0", `"0"`, "null", `""`:
		*b = false
		return nil
	default:
		var n int
		if err := json.Unmarshal(raw, &n); err == nil {
			*b = n != 0
			return nil
		}
		return fmt.Errorf("invalid boolean value %s", s)
	}
}

type Client struct {
	apiBase *url.URL
	http    *http.Client
	token   string
}

func NewClient(creds Credentials) (*Client, error) {
	u, err := normalizeAPIBase(creds.BaseURL)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: creds.TLSSkipVerify} //nolint:gosec -- explicit admin opt-in for private/self-signed migration targets
	sourceHost := u.Host
	c := &Client{apiBase: u, http: &http.Client{Transport: transport, Timeout: 15 * time.Second}}
	c.http.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("too many redirects")
		}
		if !strings.EqualFold(req.URL.Host, sourceHost) {
			return errors.New("refusing redirect to a different host")
		}
		return nil
	}
	return c, nil
}

func normalizeAPIBase(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("source URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("invalid source URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("source URL must use http or https")
	}
	if u.Host == "" || u.User != nil {
		return nil, errors.New("source URL must contain a host and no embedded credentials")
	}
	u.RawQuery, u.Fragment = "", ""
	clean := strings.TrimSuffix(path.Clean("/"+strings.TrimSpace(u.Path)), "/")
	if clean == "." || clean == "/" {
		clean = "/api"
	} else if !strings.HasSuffix(clean, "/api") {
		clean += "/api"
	}
	u.Path = clean
	return u, nil
}

func (c *Client) endpoint(p string) string {
	u := *c.apiBase
	u.Path = strings.TrimSuffix(c.apiBase.Path, "/") + "/" + strings.TrimPrefix(p, "/")
	return u.String()
}

func (c *Client) endpointQuery(p string, q url.Values) string {
	u := *c.apiBase
	u.Path = strings.TrimSuffix(c.apiBase.Path, "/") + "/" + strings.TrimPrefix(p, "/")
	u.RawQuery = q.Encode()
	return u.String()
}

func (c *Client) Authenticate(ctx context.Context, identity, secret string) error {
	identity = strings.TrimSpace(identity)
	if identity == "" || secret == "" {
		return errors.New("identity and password are required")
	}
	body, _ := json.Marshal(map[string]string{"identity": identity, "secret": secret})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint("tokens"), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	var out struct {
		Token       string `json:"token"`
		Requires2FA bool   `json:"requires_2fa"`
	}
	if err := c.doJSON(req, &out); err != nil {
		return fmt.Errorf("source login failed: %w", err)
	}
	if out.Requires2FA {
		return errors.New("source account requires two-factor authentication; 2FA migration login is not supported yet")
	}
	if strings.TrimSpace(out.Token) == "" {
		return errors.New("source login returned no token")
	}
	c.token = out.Token
	return nil
}

func (c *Client) doJSON(req *http.Request, out any) error {
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	limited := io.LimitReader(res.Body, maxResponseBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if len(raw) > maxResponseBytes {
		return errors.New("source response is too large")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		var e struct {
			Error   any    `json:"error"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &e)
		msg := strings.TrimSpace(e.Message)
		if msg == "" && e.Error != nil {
			msg = fmt.Sprint(e.Error)
		}
		if msg == "" {
			msg = http.StatusText(res.StatusCode)
		}
		return fmt.Errorf("HTTP %d: %s", res.StatusCode, msg)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("invalid JSON from source: %w", err)
	}
	return nil
}

func (c *Client) get(ctx context.Context, p string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint(p), nil)
	if err != nil {
		return err
	}
	return c.doJSON(req, out)
}
func (c *Client) getQuery(ctx context.Context, p string, q url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpointQuery(p, q), nil)
	if err != nil {
		return err
	}
	return c.doJSON(req, out)
}

func (c *Client) sourceVersion(ctx context.Context) string {
	var out struct {
		Version any `json:"version"`
	}
	if err := c.get(ctx, "", &out); err != nil {
		return ""
	}
	switch v := out.Version.(type) {
	case string:
		return v
	case map[string]any:
		parts := make([]string, 0, 3)
		for _, k := range []string{"major", "minor", "revision"} {
			if x, ok := v[k]; ok {
				parts = append(parts, fmt.Sprint(x))
			}
		}
		return strings.Join(parts, ".")
	default:
		return ""
	}
}

func (c *Client) ProxyHosts(ctx context.Context) ([]npmProxyHost, error) {
	out := []npmProxyHost{}
	if err := c.get(ctx, "nginx/proxy-hosts", &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) Certificates(ctx context.Context) ([]npmCertificate, error) {
	out := []npmCertificate{}
	if err := c.get(ctx, "nginx/certificates", &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) AccessLists(ctx context.Context) ([]npmAccessList, error) {
	out := []npmAccessList{}
	if err := c.getQuery(ctx, "nginx/access-lists", url.Values{"expand": {"items,clients"}}, &out); err != nil {
		return nil, err
	}
	// Some source versions only expand child collections on the item endpoint.
	for i := range out {
		if out[i].ID < 1 || out[i].Items != nil || out[i].Clients != nil {
			continue
		}
		var one npmAccessList
		if err := c.getQuery(ctx, fmt.Sprintf("nginx/access-lists/%d", out[i].ID), url.Values{"expand": {"items,clients"}}, &one); err == nil {
			out[i] = one
		}
	}
	return out, nil
}
func (c *Client) RedirectHosts(ctx context.Context) ([]npmRedirectHost, error) {
	out := []npmRedirectHost{}
	if err := c.get(ctx, "nginx/redirection-hosts", &out); err != nil {
		return nil, err
	}
	return out, nil
}
func (c *Client) DeadHosts(ctx context.Context) ([]npmDeadHost, error) {
	out := []npmDeadHost{}
	if err := c.get(ctx, "nginx/dead-hosts", &out); err != nil {
		return nil, err
	}
	return out, nil
}
func (c *Client) Streams(ctx context.Context) ([]npmStream, error) {
	out := []npmStream{}
	if err := c.get(ctx, "nginx/streams", &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c *Client) count(ctx context.Context, endpoint string) (int, error) {
	var out []json.RawMessage
	if err := c.get(ctx, endpoint, &out); err != nil {
		return 0, err
	}
	return len(out), nil
}

func Analyze(ctx context.Context, creds Credentials, existing []model.Host) (Analysis, error) {
	c, err := NewClient(creds)
	if err != nil {
		return Analysis{}, err
	}
	if err := c.Authenticate(ctx, creds.Identity, creds.Secret); err != nil {
		return Analysis{}, err
	}
	src := SourceInfo{URL: c.apiBase.Scheme + "://" + c.apiBase.Host, Version: c.sourceVersion(ctx)}
	sourceHosts, err := c.ProxyHosts(ctx)
	if err != nil {
		return Analysis{}, fmt.Errorf("cannot read proxy hosts: %w", err)
	}
	sourceCerts, certErr := c.Certificates(ctx)
	sourceAccess, accessErr := c.AccessLists(ctx)
	sourceRedirects, redirectErr := c.RedirectHosts(ctx)
	sourceDead, deadErr := c.DeadHosts(ctx)
	sourceStreams, streamErr := c.Streams(ctx)

	result := Analysis{
		Source: src, Resources: []ResourceCount{}, ProxyHosts: []ProxyHostPlan{}, Certificates: []CertificatePlan{},
		AccessLists: []AccessListPlan{}, Redirects: []RedirectHostPlan{}, DeadHosts: []DeadHostPlan{}, Streams: []StreamPlan{}, GeneralNotes: []string{},
	}
	certPlans := map[int64]CertificatePlan{}
	if certErr == nil {
		for _, cert := range sourceCerts {
			p := mapCertificate(cert, creds)
			certPlans[cert.ID] = p
			result.Certificates = append(result.Certificates, p)
		}
		sort.Slice(result.Certificates, func(i, j int) bool { return result.Certificates[i].Name < result.Certificates[j].Name })
	} else {
		result.GeneralNotes = append(result.GeneralNotes, "Certificate details could not be read: "+safeErr(certErr))
	}

	accessPlans := map[int64]AccessListPlan{}
	if accessErr == nil {
		for _, a := range sourceAccess {
			p := mapAccessList(a)
			accessPlans[a.ID] = p
			result.AccessLists = append(result.AccessLists, p)
		}
	} else {
		result.GeneralNotes = append(result.GeneralNotes, "Access lists could not be read: "+safeErr(accessErr))
	}
	if redirectErr == nil {
		for _, r := range sourceRedirects {
			result.Redirects = append(result.Redirects, mapRedirectHost(r, certPlans))
		}
	} else {
		result.GeneralNotes = append(result.GeneralNotes, "Redirect hosts could not be read: "+safeErr(redirectErr))
	}
	if deadErr == nil {
		for _, d := range sourceDead {
			result.DeadHosts = append(result.DeadHosts, mapDeadHost(d, certPlans))
		}
	} else {
		result.GeneralNotes = append(result.GeneralNotes, "404 hosts could not be read: "+safeErr(deadErr))
	}
	if streamErr == nil {
		for _, st := range sourceStreams {
			result.Streams = append(result.Streams, mapStream(st, certPlans))
		}
	} else {
		result.GeneralNotes = append(result.GeneralNotes, "Streams could not be read: "+safeErr(streamErr))
	}

	result.Resources = append(result.Resources,
		ResourceCount{Key: "proxy-hosts", Label: "Proxy hosts", Count: len(sourceHosts), Importable: true, Note: "Migrated with routing, TLS, access control, custom locations and advanced configuration."},
		resourceCount("redirection-hosts", "Redirection hosts", len(sourceRedirects), redirectErr, allRedirectsImportable(result.Redirects), "Migrated as native redirect hosts."),
		resourceCount("streams", "Streams", len(sourceStreams), streamErr, allStreamsImportable(result.Streams), "Migrated as native TCP/UDP streams; Docker/Unraid still needs the incoming ports exposed."),
		resourceCount("dead-hosts", "404 hosts", len(sourceDead), deadErr, allDeadImportable(result.DeadHosts), "Migrated as native 404 hosts."),
		resourceCount("access-lists", "Access lists", len(sourceAccess), accessErr, allAccessImportable(result.AccessLists), "IP rules are migrated; Basic Auth requires the optional read-only source data mount."),
		resourceCount("certificates", "Certificates", len(sourceCerts), certErr, allCertificatesImportable(result.Certificates), "Existing certificate material is copied when available; renewable Let's Encrypt certificates are reissued when source files are unavailable."),
	)
	userCount, userErr := c.count(ctx, "users")
	result.Resources = append(result.Resources, resourceCount("users", "Users", userCount, userErr, false, "Administrator accounts are intentionally not copied; keep the ZentProxy administrator account."))

	occupied := append([]model.Host{}, existing...)
	for _, srcHost := range sourceHosts {
		p := mapProxyHost(srcHost, certPlans, accessPlans)
		if p.Importable {
			if err := proxy.CheckDomainConflicts(occupied, p.Domains, -1); err != nil {
				p.Importable = false
				p.Conflict = err.Error()
			}
		}
		if p.Importable {
			occupied = append(occupied, model.Host{Name: p.Name, Domains: append([]string{}, p.Domains...)})
			result.Importable++
		} else {
			result.Blocked++
		}
		result.ProxyHosts = append(result.ProxyHosts, p)
	}
	for i := range result.Resources {
		if result.Resources[i].Key == "proxy-hosts" {
			result.Resources[i].Importable = result.Blocked == 0
			if result.Blocked > 0 {
				result.Resources[i].Note = fmt.Sprintf("%d proxy host(s) are blocked by a dependency or domain conflict; full migration will not start until they are resolved.", result.Blocked)
			}
			break
		}
	}
	sort.Slice(result.ProxyHosts, func(i, j int) bool { return result.ProxyHosts[i].Name < result.ProxyHosts[j].Name })
	if result.Blocked > 0 {
		result.GeneralNotes = append(result.GeneralNotes, "Blocked proxy hosts are never imported partially. Resolve the listed dependency/conflict first.")
	}
	if anyNeedsFullMount(result.Certificates, result.AccessLists) {
		result.GeneralNotes = append(result.GeneralNotes, "For a lossless migration, mount the source data read-only at /migration/data and the source Let's Encrypt directory at /migration/letsencrypt. The remote API does not expose all secret material.")
	}
	return result, nil
}

func resourceCount(key, label string, count int, err error, importable bool, note string) ResourceCount {
	if err != nil {
		return ResourceCount{Key: key, Label: label, Count: -1, Importable: false, Note: "Could not read this resource: " + safeErr(err)}
	}
	return ResourceCount{Key: key, Label: label, Count: count, Importable: importable, Note: note}
}
func allCertificatesImportable(in []CertificatePlan) bool {
	for _, x := range in {
		if !x.Importable {
			return false
		}
	}
	return true
}
func allAccessImportable(in []AccessListPlan) bool {
	for _, x := range in {
		if !x.Importable {
			return false
		}
	}
	return true
}
func allRedirectsImportable(in []RedirectHostPlan) bool {
	for _, x := range in {
		if !x.Importable {
			return false
		}
	}
	return true
}
func allDeadImportable(in []DeadHostPlan) bool {
	for _, x := range in {
		if !x.Importable {
			return false
		}
	}
	return true
}
func allStreamsImportable(in []StreamPlan) bool {
	for _, x := range in {
		if !x.Importable {
			return false
		}
	}
	return true
}
func anyNeedsFullMount(certs []CertificatePlan, access []AccessListPlan) bool {
	for _, c := range certs {
		if !c.Importable && strings.Contains(strings.ToLower(c.Warning), "mount") {
			return true
		}
	}
	for _, a := range access {
		if !a.Importable && strings.Contains(strings.ToLower(a.Warning), "mount") {
			return true
		}
	}
	return false
}

func mapProxyHost(src npmProxyHost, certPlans map[int64]CertificatePlan, accessPlans map[int64]AccessListPlan) ProxyHostPlan {
	domains := make([]string, 0, len(src.DomainNames))
	seen := map[string]bool{}
	for _, d := range src.DomainNames {
		d = strings.ToLower(strings.TrimSpace(d))
		if d != "" && !seen[d] {
			seen[d] = true
			domains = append(domains, d)
		}
	}
	sort.Strings(domains)
	name := "Imported proxy host " + strconv.FormatInt(src.ID, 10)
	if len(domains) > 0 {
		name = domains[0]
	}
	scheme := strings.ToLower(strings.TrimSpace(src.ForwardScheme))
	if scheme == "" {
		scheme = "http"
	}
	in := model.HostInput{
		Name: name, Domains: domains, Scheme: scheme,
		ForwardHost: strings.TrimSpace(src.ForwardHost), ForwardPort: src.ForwardPort,
		Enabled: bool(src.Enabled), WebSockets: bool(src.AllowWebsocketUpgrade), PreserveHost: true,
		StatisticsEnabled: true, StoreQueryString: false, BlockCommonExploits: bool(src.BlockExploits),
		SSLForced: bool(src.SSLForced), HTTP2Support: bool(src.HTTP2Support), HSTSEnabled: bool(src.HSTSEnabled), HSTSSubdomains: bool(src.HSTSSubdomains),
		CachingEnabled: bool(src.CachingEnabled), TrustForwardedProto: bool(src.TrustForwardedProto), AdvancedConfig: normalizeImportedAdvancedConfig(src.AdvancedConfig), CustomLocations: mapLocations(src.Locations),
	}
	normalized, err := proxy.NormalizeAndValidate(in)
	p := ProxyHostPlan{SourceID: src.ID, SourceCertificateID: src.CertificateID, SourceAccessListID: src.AccessListID, Name: name, Domains: domains, Enabled: in.Enabled, Warnings: []string{}, Input: normalized}
	p.Upstream = fmt.Sprintf("%s://%s:%d", scheme, in.ForwardHost, in.ForwardPort)
	if err != nil {
		p.Importable = false
		p.Conflict = err.Error()
		return p
	}
	p.Importable = true
	if src.CertificateID > 0 {
		cp, ok := certPlans[src.CertificateID]
		if !ok || !cp.Importable {
			p.Importable = false
			p.Conflict = "TLS certificate cannot be migrated safely"
			if ok && cp.Warning != "" {
				p.Conflict += ": " + cp.Warning
			}
			return p
		}
	}
	if src.AccessListID > 0 {
		ap, ok := accessPlans[src.AccessListID]
		if !ok || !ap.Importable {
			p.Importable = false
			p.Conflict = "access list cannot be migrated safely"
			if ok && ap.Warning != "" {
				p.Conflict += ": " + ap.Warning
			}
			return p
		}
	}
	return p
}

func mapAccessList(src npmAccessList) AccessListPlan {
	name := strings.TrimSpace(src.Name)
	if name == "" {
		name = fmt.Sprintf("Imported access list %d", src.ID)
	}
	rules := make([]model.AccessRule, 0, len(src.Clients))
	for _, c := range src.Clients {
		directive := strings.ToLower(strings.TrimSpace(c.Directive))
		address := strings.TrimSpace(c.Address)
		if (directive == "allow" || directive == "deny") && address != "" {
			rules = append(rules, model.AccessRule{Address: address, Directive: directive})
		}
	}
	p := AccessListPlan{SourceID: src.ID, Name: name, Importable: true, Input: model.AccessListInput{Name: name, SatisfyAny: bool(src.SatisfyAny), PassAuth: bool(src.PassAuth), AuthEnabled: len(src.Items) > 0, Rules: rules}}
	if len(src.Items) > 0 {
		for _, candidate := range []string{
			filepath.Join("/migration/data", "access", strconv.FormatInt(src.ID, 10)),
			filepath.Join("/migration/data", "access", strconv.FormatInt(src.ID, 10)+".htpasswd"),
		} {
			if st, err := os.Stat(candidate); err == nil && st.Mode().IsRegular() && st.Size() > 0 {
				p.AuthSource = candidate
				return p
			}
		}
		// Passwords returned by the source API are intentionally masked. Do not silently
		// create an access list that would lose Basic Auth protection.
		p.Importable = false
		p.Warning = "Basic Auth data is not exposed by the remote API; mount the source data read-only at /migration/data"
	}
	return p
}

func normalizeNames(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		v := strings.ToLower(strings.TrimSpace(raw))
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func certDependencyOK(id int64, certPlans map[int64]CertificatePlan) (bool, string) {
	if id < 1 {
		return true, ""
	}
	cp, ok := certPlans[id]
	if !ok {
		return false, "certificate metadata is unavailable"
	}
	if !cp.Importable {
		return false, cp.Warning
	}
	return true, ""
}

func mapRedirectHost(src npmRedirectHost, certPlans map[int64]CertificatePlan) RedirectHostPlan {
	domains := normalizeNames(src.DomainNames)
	p := RedirectHostPlan{SourceID: src.ID, SourceCertificateID: src.CertificateID, Domains: domains, Importable: true}
	code := src.ForwardHTTPCode
	if code < 300 || code > 399 {
		code = 301
	}
	scheme := strings.ToLower(strings.TrimSpace(src.ForwardScheme))
	if scheme != "http" && scheme != "https" && scheme != "auto" {
		scheme = "auto"
	}
	p.Input = model.RedirectHostInput{Domains: domains, ForwardHTTPCode: code, ForwardScheme: scheme, ForwardDomainName: strings.TrimSpace(src.ForwardDomainName), PreservePath: bool(src.PreservePath), SSLForced: bool(src.SSLForced), HTTP2Support: bool(src.HTTP2Support), HSTSEnabled: bool(src.HSTSEnabled), HSTSSubdomains: bool(src.HSTSSubdomains), BlockExploits: bool(src.BlockExploits), AdvancedConfig: normalizeImportedAdvancedConfig(src.AdvancedConfig), Enabled: bool(src.Enabled)}
	if len(domains) == 0 || p.Input.ForwardDomainName == "" {
		p.Importable = false
		p.Warning = "redirect is missing domain or target"
		return p
	}
	if ok, why := certDependencyOK(src.CertificateID, certPlans); !ok {
		p.Importable = false
		p.Warning = "TLS certificate cannot be migrated safely: " + why
	}
	return p
}
func mapDeadHost(src npmDeadHost, certPlans map[int64]CertificatePlan) DeadHostPlan {
	domains := normalizeNames(src.DomainNames)
	p := DeadHostPlan{SourceID: src.ID, SourceCertificateID: src.CertificateID, Domains: domains, Importable: true, Input: model.DeadHostInput{Domains: domains, SSLForced: bool(src.SSLForced), HTTP2Support: bool(src.HTTP2Support), HSTSEnabled: bool(src.HSTSEnabled), HSTSSubdomains: bool(src.HSTSSubdomains), AdvancedConfig: normalizeImportedAdvancedConfig(src.AdvancedConfig), Enabled: bool(src.Enabled)}}
	if len(domains) == 0 {
		p.Importable = false
		p.Warning = "404 host has no domains"
		return p
	}
	if ok, why := certDependencyOK(src.CertificateID, certPlans); !ok {
		p.Importable = false
		p.Warning = "TLS certificate cannot be migrated safely: " + why
	}
	return p
}
func mapStream(src npmStream, certPlans map[int64]CertificatePlan) StreamPlan {
	p := StreamPlan{SourceID: src.ID, SourceCertificateID: src.CertificateID, IncomingPort: src.IncomingPort, Importable: true, Input: model.StreamInput{IncomingPort: src.IncomingPort, ForwardHost: strings.TrimSpace(src.ForwardHost), ForwardPort: src.ForwardPort, TCPForwarding: bool(src.TCPForwarding), UDPForwarding: bool(src.UDPForwarding), Enabled: bool(src.Enabled)}}
	if src.IncomingPort < 1 || src.IncomingPort > 65535 || src.ForwardPort < 1 || src.ForwardPort > 65535 || p.Input.ForwardHost == "" || (!p.Input.TCPForwarding && !p.Input.UDPForwarding) {
		p.Importable = false
		p.Warning = "stream has invalid port, target or protocol"
		return p
	}
	if ok, why := certDependencyOK(src.CertificateID, certPlans); !ok {
		p.Importable = false
		p.Warning = "TLS certificate cannot be migrated safely: " + why
	}
	return p
}

func normalizeImportedAdvancedConfig(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return raw
	}
	// Imported snippets may reference a convenience variable that is not a
	// built-in OpenResty variable. ZentProxy owns a stable equivalent with a
	// scheme fallback, so imported configuration remains valid and predictable.
	return strings.ReplaceAll(raw, "$x_forwarded_proto", "$zp_forwarded_proto")
}

func mapLocations(in []npmLocation) []model.CustomLocation {
	out := make([]model.CustomLocation, 0, len(in))
	for _, l := range in {
		out = append(out, model.CustomLocation{Path: l.Path, Scheme: l.ForwardScheme, ForwardHost: l.ForwardHost, ForwardPort: l.ForwardPort, ForwardPath: l.ForwardPath, AdvancedConfig: normalizeImportedAdvancedConfig(l.AdvancedConfig)})
	}
	return out
}

func mapCertificate(src npmCertificate, creds Credentials) CertificatePlan {
	name := strings.TrimSpace(src.NiceName)
	if name == "" && len(src.DomainNames) > 0 {
		name = src.DomainNames[0]
	}
	p := CertificatePlan{SourceID: src.ID, Name: name, Provider: src.Provider, Domains: append([]string{}, src.DomainNames...), ExpiresOn: src.ExpiresOn}
	input := model.CertificateImportInput{Name: name, Domains: append([]string{}, src.DomainNames...), Provider: "custom", AutoRenew: false}
	certPEM, keyPEM := strings.TrimSpace(src.Meta.Certificate), strings.TrimSpace(src.Meta.CertificateKey)
	renewalSafe := true
	if strings.EqualFold(src.Provider, "letsencrypt") {
		input.Provider = "imported-letsencrypt"
		input.Email = strings.TrimSpace(src.Meta.LetsEncryptEmail)
		if input.Email == "" {
			// Older/source API responses may omit the ACME account address even though
			// the source database has it. The login identity is a useful fallback when
			// it is itself an email address, but we never enable renewal with a value
			// that fails mail validation below.
			input.Email = strings.TrimSpace(creds.Identity)
		}
		input.AutoRenew = true
		input.Challenge = "http-01"
		if bool(src.Meta.DNSChallenge) {
			input.Challenge = "dns-01"
			credentialText := src.Meta.DNSProviderCredentials
			// The source keeps the effective certbot credential file in the
			// Let's Encrypt volume. Prefer that read-only material when mounted;
			// it also covers API responses that intentionally omit or mask secrets.
			credentialFile := filepath.Join("/migration/letsencrypt", "credentials", fmt.Sprintf("credentials-%d", src.ID))
			if raw, err := os.ReadFile(credentialFile); err == nil && len(raw) > 0 {
				credentialText = string(raw)
			}
			input.DNSProvider, input.DNSCredentials = translateDNSProvider(src.Meta.DNSProvider, credentialText)
		}
		live := filepath.Join("/migration/letsencrypt", "live", fmt.Sprintf("npm-%d", src.ID))
		if raw, err := os.ReadFile(filepath.Join(live, "fullchain.pem")); err == nil {
			certPEM = string(raw)
		}
		if raw, err := os.ReadFile(filepath.Join(live, "privkey.pem")); err == nil {
			keyPEM = string(raw)
		}
		if certPEM != "" && keyPEM != "" {
			p.MaterialSource = "existing certificate"
		} else {
			p.Reissue = true
			p.MaterialSource = "reissue after migration"
			p.Warning = "source certificate files are unavailable; ZentProxy will issue a new Let's Encrypt certificate during migration"
		}
		if _, err := mail.ParseAddress(input.Email); err != nil {
			input.Email = ""
			input.AutoRenew = false
			renewalSafe = false
			if p.Warning != "" {
				p.Warning += "; "
			}
			p.Warning += "renewal account email is unavailable; automatic renewal cannot be preserved"
		}
		if input.Challenge == "dns-01" && (input.DNSProvider == "" || len(input.DNSCredentials) == 0) {
			input.AutoRenew = false
			renewalSafe = false
			if p.Warning != "" {
				p.Warning += "; "
			}
			p.Warning += "DNS provider credentials could not be translated for automatic renewal; configure a supported migration translator before importing"
		}
	} else {
		customDir := filepath.Join("/migration/data", "custom_ssl", fmt.Sprintf("npm-%d", src.ID))
		if raw, err := os.ReadFile(filepath.Join(customDir, "fullchain.pem")); err == nil {
			certPEM = string(raw)
		}
		if raw, err := os.ReadFile(filepath.Join(customDir, "privkey.pem")); err == nil {
			keyPEM = string(raw)
		}
		if certPEM != "" && keyPEM != "" {
			if strings.HasPrefix(customDir, "/migration/data") {
				p.MaterialSource = "existing custom certificate"
			} else {
				p.MaterialSource = "API certificate material"
			}
		} else {
			p.Warning = "custom certificate material is unavailable; mount the source data read-only at /migration/data"
		}
	}
	input.CertificatePEM = certPEM
	input.PrivateKeyPEM = keyPEM
	p.Input = input
	if p.Reissue {
		p.Importable = renewalSafe
	} else {
		p.Importable = certPEM != "" && keyPEM != "" && renewalSafe
	}
	if p.Importable && !p.Reissue {
		if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
			p.Importable = false
			if p.Warning != "" {
				p.Warning += "; "
			}
			p.Warning += "certificate/private key material is invalid or does not match"
		}
	}
	return p
}

var credentialLineRE = regexp.MustCompile(`(?m)^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$`)

func translateDNSProvider(provider, raw string) (string, map[string]string) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	vals := map[string]string{}
	for _, m := range credentialLineRE.FindAllStringSubmatch(raw, -1) {
		v := strings.Trim(strings.TrimSpace(m[2]), "'\"")
		vals[strings.ToLower(m[1])] = v
	}
	switch provider {
	case "cloudflare", "dns_cf":
		out := map[string]string{}
		if v := vals["dns_cloudflare_api_token"]; v != "" {
			out["CF_DNS_API_TOKEN"] = v
		}
		if v := vals["dns_cloudflare_email"]; v != "" {
			out["CF_API_EMAIL"] = v
		}
		if v := vals["dns_cloudflare_api_key"]; v != "" {
			out["CF_API_KEY"] = v
		}
		return "cloudflare", out
	default:
		return "", nil
	}
}

func PrepareBatch(ctx context.Context, creds Credentials, existing []model.Host, sourceIDs []int64) (Batch, error) {
	analysis, err := Analyze(ctx, creds, existing)
	if err != nil {
		return Batch{}, err
	}
	for _, resource := range analysis.Resources {
		if resource.Key == "users" {
			continue
		}
		if resource.Count < 0 {
			return Batch{}, fmt.Errorf("%s could not be read from the source; refusing a partial migration", resource.Label)
		}
		if resource.Count > 0 && !resource.Importable {
			return Batch{}, fmt.Errorf("%s is not fully importable: %s", resource.Label, resource.Note)
		}
	}
	if analysis.Blocked > 0 {
		return Batch{}, errors.New("one or more proxy hosts are blocked; refusing a partial migration")
	}
	selected := map[int64]bool{}
	for _, id := range sourceIDs {
		if id > 0 {
			selected[id] = true
		}
	}
	batch := Batch{Hosts: []ProxyHostPlan{}, Certificates: []CertificatePlan{}, AccessLists: []AccessListPlan{}, Redirects: []RedirectHostPlan{}, DeadHosts: []DeadHostPlan{}, Streams: []StreamPlan{}, Warnings: []string{}}
	neededCerts := map[int64]bool{}
	neededAccess := map[int64]bool{}
	for _, p := range analysis.ProxyHosts {
		if len(selected) > 0 && !selected[p.SourceID] {
			continue
		}
		if !p.Importable {
			return batch, fmt.Errorf("proxy host %s is blocked: %s", p.Name, p.Conflict)
		}
		batch.Hosts = append(batch.Hosts, p)
		if p.SourceCertificateID > 0 {
			neededCerts[p.SourceCertificateID] = true
		}
		if p.SourceAccessListID > 0 {
			neededAccess[p.SourceAccessListID] = true
		}
	}
	if len(batch.Hosts) == 0 && len(analysis.Redirects) == 0 && len(analysis.DeadHosts) == 0 && len(analysis.Streams) == 0 {
		return batch, errors.New("no importable routing objects found")
	}
	// Full migration keeps standalone access lists and certificates too, not just references
	// from the selected proxy-host rows.
	for _, a := range analysis.AccessLists {
		if !a.Importable {
			return batch, fmt.Errorf("access list %s is not importable: %s", a.Name, a.Warning)
		}
		batch.AccessLists = append(batch.AccessLists, a)
		neededAccess[a.SourceID] = true
	}
	for _, r := range analysis.Redirects {
		if !r.Importable {
			return batch, fmt.Errorf("redirect host %v is not importable: %s", r.Domains, r.Warning)
		}
		batch.Redirects = append(batch.Redirects, r)
		if r.SourceCertificateID > 0 {
			neededCerts[r.SourceCertificateID] = true
		}
	}
	for _, d := range analysis.DeadHosts {
		if !d.Importable {
			return batch, fmt.Errorf("404 host %v is not importable: %s", d.Domains, d.Warning)
		}
		batch.DeadHosts = append(batch.DeadHosts, d)
		if d.SourceCertificateID > 0 {
			neededCerts[d.SourceCertificateID] = true
		}
	}
	for _, st := range analysis.Streams {
		if !st.Importable {
			return batch, fmt.Errorf("stream %d is not importable: %s", st.IncomingPort, st.Warning)
		}
		batch.Streams = append(batch.Streams, st)
		if st.SourceCertificateID > 0 {
			neededCerts[st.SourceCertificateID] = true
		}
	}
	for _, c := range analysis.Certificates {
		// Preserve all certificates in a full migration, including currently unassigned ones.
		neededCerts[c.SourceID] = true
		if !c.Importable {
			return batch, fmt.Errorf("certificate %s is not importable: %s", c.Name, c.Warning)
		}
	}
	for _, c := range analysis.Certificates {
		if neededCerts[c.SourceID] {
			batch.Certificates = append(batch.Certificates, c)
		}
	}
	_ = neededAccess // retained as explicit dependency map for future selective object migration.
	if len(batch.Streams) > 0 {
		batch.Warnings = append(batch.Warnings, "TCP/UDP stream objects are migrated, but their incoming ports must also be published by the ZentProxy Docker/Unraid container.")
	}
	return batch, nil
}

func safeErr(err error) string {
	s := strings.ReplaceAll(err.Error(), "\n", " ")
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}
