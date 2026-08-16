package providers

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ZentWorks/ZentProxy/internal/db"
	"github.com/ZentWorks/ZentProxy/internal/model"
)

type Manager struct {
	store    *db.Store
	client   *http.Client
	every    time.Duration
	onChange func() error
	mu       sync.Mutex
}

func New(store *db.Store, every time.Duration, onChange func() error) *Manager {
	return &Manager{store: store, every: every, onChange: onChange, client: &http.Client{Timeout: 15 * time.Second}}
}

func (m *Manager) Start(ctx context.Context) {
	go func() {
		m.RefreshAll(ctx)
		t := time.NewTicker(m.every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.RefreshAll(ctx)
			}
		}
	}()
}

func (m *Manager) RefreshAll(ctx context.Context) {
	providers, err := m.store.ListProviders()
	if err != nil {
		return
	}
	for _, p := range providers {
		if p.AutoUpdate {
			_, _ = m.Refresh(ctx, p.ID)
		}
	}
}

func (m *Manager) Refresh(ctx context.Context, id int64) (model.TrustedProxyProvider, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, err := m.store.GetProvider(id)
	if err != nil {
		return p, err
	}
	if !p.AutoUpdate {
		return p, fmt.Errorf("provider is not auto-updated")
	}
	var all []string
	for _, u := range []string{p.SourceIPv4, p.SourceIPv6} {
		if strings.TrimSpace(u) == "" {
			continue
		}
		items, err := m.fetchCIDRs(ctx, u)
		if err != nil {
			_ = m.store.UpdateProviderResult(id, p.CIDRs, time.Now().UTC(), false, err.Error())
			return m.store.GetProvider(id)
		}
		all = append(all, items...)
	}
	all = uniqueSorted(all)
	changed := !sameStrings(all, p.CIDRs)
	if err := m.store.UpdateProviderResult(id, all, time.Now().UTC(), changed, ""); err != nil {
		return p, err
	}
	if changed && m.onChange != nil {
		if err := m.onChange(); err != nil {
			return p, err
		}
	}
	return m.store.GetProvider(id)
}

func (m *Manager) fetchCIDRs(ctx context.Context, u string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ZentProxy trusted-proxy updater")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("provider returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR from provider: %q", line)
		}
		out = append(out, prefix.Masked().String())
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("provider returned no CIDR ranges")
	}
	return uniqueSorted(out), nil
}

func uniqueSorted(in []string) []string {
	m := map[string]struct{}{}
	for _, v := range in {
		m[v] = struct{}{}
	}
	out := make([]string, 0, len(m))
	for v := range m {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aa := append([]string{}, a...)
	bb := append([]string{}, b...)
	sort.Strings(aa)
	sort.Strings(bb)
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}
