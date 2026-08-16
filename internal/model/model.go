package model

import "time"

type CustomLocation struct {
	Path           string `json:"path"`
	Scheme         string `json:"scheme"`
	ForwardHost    string `json:"forward_host"`
	ForwardPort    int    `json:"forward_port"`
	ForwardPath    string `json:"forward_path,omitempty"`
	AdvancedConfig string `json:"advanced_config,omitempty"`
}

type Host struct {
	ID                     int64            `json:"id"`
	Name                   string           `json:"name"`
	Domains                []string         `json:"domains"`
	Scheme                 string           `json:"scheme"`
	ForwardHost            string           `json:"forward_host"`
	ForwardPort            int              `json:"forward_port"`
	Enabled                bool             `json:"enabled"`
	WebSockets             bool             `json:"websockets"`
	PreserveHost           bool             `json:"preserve_host"`
	StatisticsEnabled      bool             `json:"statistics_enabled"`
	StoreQueryString       bool             `json:"store_query_string"`
	TrustedProxyProviderID *int64           `json:"trusted_proxy_provider_id,omitempty"`
	AccessListID           *int64           `json:"access_list_id,omitempty"`
	BlockCommonExploits    bool             `json:"block_common_exploits"`
	CertificateID          *int64           `json:"certificate_id,omitempty"`
	SSLForced              bool             `json:"ssl_forced"`
	HTTP2Support           bool             `json:"http2_support"`
	HSTSEnabled            bool             `json:"hsts_enabled"`
	HSTSSubdomains         bool             `json:"hsts_subdomains"`
	CachingEnabled         bool             `json:"caching_enabled"`
	TrustForwardedProto    bool             `json:"trust_forwarded_proto"`
	AdvancedConfig         string           `json:"advanced_config,omitempty"`
	CustomLocations        []CustomLocation `json:"custom_locations"`
	CreatedAt              time.Time        `json:"created_at"`
	UpdatedAt              time.Time        `json:"updated_at"`
}

type HostInput struct {
	Name                   string           `json:"name"`
	Domains                []string         `json:"domains"`
	Scheme                 string           `json:"scheme"`
	ForwardHost            string           `json:"forward_host"`
	ForwardPort            int              `json:"forward_port"`
	Enabled                bool             `json:"enabled"`
	WebSockets             bool             `json:"websockets"`
	PreserveHost           bool             `json:"preserve_host"`
	StatisticsEnabled      bool             `json:"statistics_enabled"`
	StoreQueryString       bool             `json:"store_query_string"`
	TrustedProxyProviderID *int64           `json:"trusted_proxy_provider_id,omitempty"`
	AccessListID           *int64           `json:"access_list_id,omitempty"`
	BlockCommonExploits    bool             `json:"block_common_exploits"`
	CertificateID          *int64           `json:"certificate_id,omitempty"`
	SSLForced              bool             `json:"ssl_forced"`
	HTTP2Support           bool             `json:"http2_support"`
	HSTSEnabled            bool             `json:"hsts_enabled"`
	HSTSSubdomains         bool             `json:"hsts_subdomains"`
	CachingEnabled         bool             `json:"caching_enabled"`
	TrustForwardedProto    bool             `json:"trust_forwarded_proto"`
	AdvancedConfig         string           `json:"advanced_config,omitempty"`
	CustomLocations        []CustomLocation `json:"custom_locations"`
}

type Certificate struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Provider    string     `json:"provider"`
	Domains     []string   `json:"domains"`
	Challenge   string     `json:"challenge"`
	Email       string     `json:"email,omitempty"`
	DNSProvider string     `json:"dns_provider,omitempty"`
	AutoRenew   bool       `json:"auto_renew"`
	CertPath    string     `json:"cert_path"`
	KeyPath     string     `json:"key_path"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	LastRenewed *time.Time `json:"last_renewed,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type CertificateMetadataInput struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

type CertificateInput struct {
	Name           string            `json:"name"`
	Domains        []string          `json:"domains"`
	Challenge      string            `json:"challenge"`
	Email          string            `json:"email"`
	DNSProvider    string            `json:"dns_provider,omitempty"`
	DNSCredentials map[string]string `json:"dns_credentials,omitempty"`
	AutoRenew      bool              `json:"auto_renew"`
}

type CertificateImportInput struct {
	Name           string            `json:"name"`
	Provider       string            `json:"provider"`
	Domains        []string          `json:"domains"`
	CertificatePEM string            `json:"certificate_pem"`
	PrivateKeyPEM  string            `json:"private_key_pem"`
	Challenge      string            `json:"challenge,omitempty"`
	Email          string            `json:"email,omitempty"`
	DNSProvider    string            `json:"dns_provider,omitempty"`
	DNSCredentials map[string]string `json:"dns_credentials,omitempty"`
	AutoRenew      bool              `json:"auto_renew"`
}

type AccessRule struct {
	Address   string `json:"address"`
	Directive string `json:"directive"`
}

type AccessList struct {
	ID          int64        `json:"id"`
	Name        string       `json:"name"`
	SatisfyAny  bool         `json:"satisfy_any"`
	PassAuth    bool         `json:"pass_auth"`
	AuthEnabled bool         `json:"auth_enabled"`
	Rules       []AccessRule `json:"rules"`
	AuthFile    string       `json:"auth_file,omitempty"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

type AccessListInput struct {
	Name        string       `json:"name"`
	SatisfyAny  bool         `json:"satisfy_any"`
	PassAuth    bool         `json:"pass_auth"`
	AuthEnabled bool         `json:"auth_enabled"`
	Rules       []AccessRule `json:"rules"`
	AuthFile    string       `json:"auth_file,omitempty"`
}

type RedirectHost struct {
	ID                int64     `json:"id"`
	Domains           []string  `json:"domains"`
	ForwardHTTPCode   int       `json:"forward_http_code"`
	ForwardScheme     string    `json:"forward_scheme"`
	ForwardDomainName string    `json:"forward_domain_name"`
	PreservePath      bool      `json:"preserve_path"`
	CertificateID     *int64    `json:"certificate_id,omitempty"`
	SSLForced         bool      `json:"ssl_forced"`
	HTTP2Support      bool      `json:"http2_support"`
	HSTSEnabled       bool      `json:"hsts_enabled"`
	HSTSSubdomains    bool      `json:"hsts_subdomains"`
	BlockExploits     bool      `json:"block_exploits"`
	AdvancedConfig    string    `json:"advanced_config,omitempty"`
	Enabled           bool      `json:"enabled"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type RedirectHostInput struct {
	Domains           []string `json:"domains"`
	ForwardHTTPCode   int      `json:"forward_http_code"`
	ForwardScheme     string   `json:"forward_scheme"`
	ForwardDomainName string   `json:"forward_domain_name"`
	PreservePath      bool     `json:"preserve_path"`
	CertificateID     *int64   `json:"certificate_id,omitempty"`
	SSLForced         bool     `json:"ssl_forced"`
	HTTP2Support      bool     `json:"http2_support"`
	HSTSEnabled       bool     `json:"hsts_enabled"`
	HSTSSubdomains    bool     `json:"hsts_subdomains"`
	BlockExploits     bool     `json:"block_exploits"`
	AdvancedConfig    string   `json:"advanced_config,omitempty"`
	Enabled           bool     `json:"enabled"`
}

type DeadHost struct {
	ID             int64     `json:"id"`
	Domains        []string  `json:"domains"`
	CertificateID  *int64    `json:"certificate_id,omitempty"`
	SSLForced      bool      `json:"ssl_forced"`
	HTTP2Support   bool      `json:"http2_support"`
	HSTSEnabled    bool      `json:"hsts_enabled"`
	HSTSSubdomains bool      `json:"hsts_subdomains"`
	AdvancedConfig string    `json:"advanced_config,omitempty"`
	Enabled        bool      `json:"enabled"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type DeadHostInput struct {
	Domains        []string `json:"domains"`
	CertificateID  *int64   `json:"certificate_id,omitempty"`
	SSLForced      bool     `json:"ssl_forced"`
	HTTP2Support   bool     `json:"http2_support"`
	HSTSEnabled    bool     `json:"hsts_enabled"`
	HSTSSubdomains bool     `json:"hsts_subdomains"`
	AdvancedConfig string   `json:"advanced_config,omitempty"`
	Enabled        bool     `json:"enabled"`
}

type Stream struct {
	ID            int64     `json:"id"`
	IncomingPort  int       `json:"incoming_port"`
	ForwardHost   string    `json:"forward_host"`
	ForwardPort   int       `json:"forward_port"`
	TCPForwarding bool      `json:"tcp_forwarding"`
	UDPForwarding bool      `json:"udp_forwarding"`
	CertificateID *int64    `json:"certificate_id,omitempty"`
	Enabled       bool      `json:"enabled"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type StreamInput struct {
	IncomingPort  int    `json:"incoming_port"`
	ForwardHost   string `json:"forward_host"`
	ForwardPort   int    `json:"forward_port"`
	TCPForwarding bool   `json:"tcp_forwarding"`
	UDPForwarding bool   `json:"udp_forwarding"`
	CertificateID *int64 `json:"certificate_id,omitempty"`
	Enabled       bool   `json:"enabled"`
}

type TrustedProxyProviderInput struct {
	Name   string   `json:"name"`
	Header string   `json:"header"`
	CIDRs  []string `json:"cidrs"`
}

type TrustedProxyProvider struct {
	ID          int64      `json:"id"`
	Slug        string     `json:"slug"`
	Name        string     `json:"name"`
	Kind        string     `json:"kind"`
	Header      string     `json:"header"`
	AutoUpdate  bool       `json:"auto_update"`
	SourceIPv4  string     `json:"source_ipv4,omitempty"`
	SourceIPv6  string     `json:"source_ipv6,omitempty"`
	CIDRs       []string   `json:"cidrs"`
	LastChecked *time.Time `json:"last_checked,omitempty"`
	LastChanged *time.Time `json:"last_changed,omitempty"`
	LastError   string     `json:"last_error,omitempty"`
}

type ZentLoopIPList struct {
	Name    string   `json:"name"`
	Entries []string `json:"entries"`
}

type ZentLoopRule struct {
	Name    string  `json:"name"`
	Enabled bool    `json:"enabled"`
	Match   string  `json:"match"`
	Value   string  `json:"value"`
	Action  string  `json:"action"`
	HostIDs []int64 `json:"host_ids,omitempty"`
}

type ZentLoopConfig struct {
	Enabled             bool             `json:"enabled"`
	ForwardUnknownHosts bool             `json:"forward_unknown_hosts"`
	Upstream            string           `json:"upstream"`
	Secret              string           `json:"secret,omitempty"`
	Fallback            string           `json:"fallback,omitempty"`
	IPLists             []ZentLoopIPList `json:"ip_lists"`
	Rules               []ZentLoopRule   `json:"rules"`
}
type APIKey struct {
	ID        int64      `json:"id"`
	Name      string     `json:"name"`
	Prefix    string     `json:"prefix"`
	Scopes    []string   `json:"scopes"`
	CreatedAt time.Time  `json:"created_at"`
	LastUsed  *time.Time `json:"last_used,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}
type RawRequest struct {
	ID             int64     `json:"id"`
	At             time.Time `json:"at"`
	Host           string    `json:"host"`
	IP             string    `json:"ip"`
	Method         string    `json:"method"`
	Path           string    `json:"path"`
	Query          string    `json:"query,omitempty"`
	Status         int       `json:"status"`
	Bytes          int64     `json:"bytes"`
	RequestTimeMS  float64   `json:"request_time_ms"`
	UpstreamTimeMS *float64  `json:"upstream_time_ms,omitempty"`
	UserAgent      string    `json:"user_agent,omitempty"`
	Referer        string    `json:"referer,omitempty"`
	HTTPVersion    string    `json:"http_version,omitempty"`
	TLSVersion     string    `json:"tls_version,omitempty"`
}
type StatsSummary struct {
	Since         time.Time        `json:"since"`
	Requests      int64            `json:"requests"`
	UniqueIPs     int64            `json:"unique_ips"`
	Bytes         int64            `json:"bytes"`
	Errors        int64            `json:"errors"`
	AverageTimeMS float64          `json:"average_time_ms"`
	StatusClasses map[string]int64 `json:"status_classes"`
	TopHosts      []CountItem      `json:"top_hosts"`
	TopPaths      []CountItem      `json:"top_paths"`
	TopIPs        []CountItem      `json:"top_ips"`
}
type CountItem struct {
	Key   string `json:"key"`
	Count int64  `json:"count"`
}
