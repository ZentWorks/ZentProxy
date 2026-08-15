package config

import (
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DataDir              string
	AdminEmail           string
	AdminEmailConfigured bool
	LegacyAdminUser      string
	AdminPassword        string
	AdminPort            int
	RawRetentionDays     int
	AnalyticsLogMaxBytes int64
	ProviderRefreshEvery time.Duration
	CookieSecure         bool
	Version              string
	Commit               string
}

func Load(version, commit string) (Config, error) {
	adminEmail := strings.TrimSpace(os.Getenv("ZENTPROXY_ADMIN_EMAIL"))
	legacyAdminUser := strings.TrimSpace(os.Getenv("ZENTPROXY_ADMIN_USER"))
	adminEmailConfigured := adminEmail != ""
	if !adminEmailConfigured && legacyAdminUser != "" {
		if _, err := mail.ParseAddress(legacyAdminUser); err == nil && strings.Contains(legacyAdminUser, "@") {
			adminEmail = legacyAdminUser
			adminEmailConfigured = true
		}
	}
	if adminEmail == "" {
		adminEmail = "admin@example.com"
	}
	adminEmail = strings.ToLower(adminEmail)

	cfg := Config{
		DataDir:              env("ZENTPROXY_DATA_DIR", "/data"),
		AdminEmail:           adminEmail,
		AdminEmailConfigured: adminEmailConfigured,
		LegacyAdminUser:      legacyAdminUser,
		AdminPassword:        os.Getenv("ZENTPROXY_ADMIN_PASSWORD"),
		AdminPort:            envInt("ZENTPROXY_ADMIN_PORT", 8080),
		RawRetentionDays:     envInt("ZENTPROXY_RAW_RETENTION_DAYS", 7),
		AnalyticsLogMaxBytes: int64(envInt("ZENTPROXY_ANALYTICS_LOG_MAX_MB", 64)) * 1024 * 1024,
		CookieSecure:         envBool("ZENTPROXY_ADMIN_COOKIE_SECURE", false),
		Version:              version,
		Commit:               commit,
	}
	refreshHours := envInt("ZENTPROXY_PROVIDER_REFRESH_HOURS", 6)
	if refreshHours < 1 {
		refreshHours = 1
	}
	cfg.ProviderRefreshEvery = time.Duration(refreshHours) * time.Hour
	if cfg.AdminPort < 1 || cfg.AdminPort > 65535 {
		return Config{}, fmt.Errorf("invalid ZENTPROXY_ADMIN_PORT")
	}
	if cfg.RawRetentionDays < 1 {
		cfg.RawRetentionDays = 1
	}
	if cfg.AnalyticsLogMaxBytes < 1024*1024 {
		cfg.AnalyticsLogMaxBytes = 1024 * 1024
	}
	parsedAdmin, err := mail.ParseAddress(strings.TrimSpace(cfg.AdminEmail))
	if err != nil || !strings.Contains(parsedAdmin.Address, "@") {
		return Config{}, fmt.Errorf("ZENTPROXY_ADMIN_EMAIL must be a valid email address")
	}
	cfg.AdminEmail = strings.ToLower(strings.TrimSpace(parsedAdmin.Address))
	abs, err := filepath.Abs(cfg.DataDir)
	if err != nil {
		return Config{}, err
	}
	cfg.DataDir = abs
	return cfg, nil
}

func env(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func envBool(key string, fallback bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}
