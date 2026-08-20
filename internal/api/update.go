package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	githubLatestReleaseURL = "https://api.github.com/repos/ZentWorks/ZentProxy/releases/latest"
	githubReleasePageURL   = "https://github.com/ZentWorks/ZentProxy/releases"
	releaseCheckTTL        = 12 * time.Hour
)

type releaseStatus struct {
	CurrentVersion  string    `json:"current_version"`
	LatestVersion   string    `json:"latest_version,omitempty"`
	UpdateAvailable bool      `json:"update_available"`
	ReleaseURL      string    `json:"release_url,omitempty"`
	CheckedAt       time.Time `json:"checked_at,omitempty"`
}

type releaseChecker struct {
	mu             sync.Mutex
	currentVersion string
	latestURL      string
	client         *http.Client
	cached         releaseStatus
	checkedAt      time.Time
}

func newReleaseChecker(currentVersion string) *releaseChecker {
	return &releaseChecker{
		currentVersion: strings.TrimSpace(currentVersion),
		latestURL:      githubLatestReleaseURL,
		client:         &http.Client{Timeout: 2500 * time.Millisecond},
	}
}

func (c *releaseChecker) status(ctx context.Context) releaseStatus {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now().UTC()
	if !c.checkedAt.IsZero() && now.Sub(c.checkedAt) < releaseCheckTTL {
		return c.cached
	}

	current, currentOK := parseSemver(c.currentVersion)
	if !currentOK {
		c.checkedAt = now
		c.cached = releaseStatus{CurrentVersion: c.currentVersion, CheckedAt: now}
		return c.cached
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.latestURL, nil)
	if err != nil {
		return c.staleOrEmpty(now)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "ZentProxy/"+c.currentVersion)

	resp, err := c.client.Do(req)
	if err != nil {
		return c.staleOrEmpty(now)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return c.staleOrEmpty(now)
	}

	var release struct {
		TagName    string `json:"tag_name"`
		HTMLURL    string `json:"html_url"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil || release.Draft || release.Prerelease {
		return c.staleOrEmpty(now)
	}
	latest, ok := parseSemver(release.TagName)
	if !ok {
		return c.staleOrEmpty(now)
	}

	releaseURL := strings.TrimSpace(release.HTMLURL)
	if releaseURL == "" || !strings.HasPrefix(releaseURL, "https://github.com/ZentWorks/ZentProxy/") {
		releaseURL = githubReleasePageURL
	}
	c.checkedAt = now
	c.cached = releaseStatus{
		CurrentVersion:  c.currentVersion,
		LatestVersion:   latest.String(),
		UpdateAvailable: latest.GreaterThan(current),
		ReleaseURL:      releaseURL,
		CheckedAt:       now,
	}
	return c.cached
}

func (c *releaseChecker) staleOrEmpty(now time.Time) releaseStatus {
	if !c.checkedAt.IsZero() {
		return c.cached
	}
	// GitHub availability must never affect the WebUI. Do not cache a first failure
	// for 12 hours; a later login can retry, while this request simply returns no badge.
	return releaseStatus{CurrentVersion: c.currentVersion, CheckedAt: now}
}

func (s *Server) systemUpdate(w http.ResponseWriter, r *http.Request) {
	if s.updates == nil {
		writeJSON(w, http.StatusOK, releaseStatus{CurrentVersion: s.cfg.Version})
		return
	}
	writeJSON(w, http.StatusOK, s.updates.status(r.Context()))
}

type semver struct{ major, minor, patch int }

func parseSemver(raw string) (semver, bool) {
	raw = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), "v"))
	if i := strings.IndexAny(raw, "+-"); i >= 0 {
		raw = raw[:i]
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return semver{}, false
	}
	nums := [3]int{}
	for i, part := range parts {
		if part == "" {
			return semver{}, false
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return semver{}, false
		}
		nums[i] = n
	}
	return semver{nums[0], nums[1], nums[2]}, true
}

func (v semver) GreaterThan(other semver) bool {
	if v.major != other.major {
		return v.major > other.major
	}
	if v.minor != other.minor {
		return v.minor > other.minor
	}
	return v.patch > other.patch
}

func (v semver) String() string { return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch) }
