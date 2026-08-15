package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/zentproxy/zentproxy/internal/analytics"
	"github.com/zentproxy/zentproxy/internal/api"
	"github.com/zentproxy/zentproxy/internal/certificates"
	"github.com/zentproxy/zentproxy/internal/config"
	"github.com/zentproxy/zentproxy/internal/db"
	"github.com/zentproxy/zentproxy/internal/providers"
	"github.com/zentproxy/zentproxy/internal/proxy"
	"github.com/zentproxy/zentproxy/internal/zentloop"
)

var version = "dev"
var commit = "unknown"

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	cfg, err := config.Load(version, commit)
	if err != nil {
		log.Fatal(err)
	}
	store, err := db.Open(cfg.DataDir)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer store.Close()
	userCount, err := store.UserCount()
	if err != nil {
		log.Fatalf("admin bootstrap: count users: %v", err)
	}
	if cfg.LegacyAdminUser != "" {
		log.Printf("WARNING: ZENTPROXY_ADMIN_USER is obsolete; use ZENTPROXY_ADMIN_EMAIL instead.")
	}
	if userCount == 0 && !cfg.AdminEmailConfigured {
		log.Fatalf("fresh installation requires ZENTPROXY_ADMIN_EMAIL to be set to a valid administrator e-mail address")
	}
	bootstrapEmail := ""
	if cfg.AdminEmailConfigured {
		bootstrapEmail = cfg.AdminEmail
	}
	generated, err := store.EnsureAdmin(bootstrapEmail, cfg.AdminPassword)
	if err != nil {
		log.Fatalf("admin bootstrap: %v", err)
	}
	if cfg.AdminEmailConfigured {
		log.Printf("ADMIN LOGIN EMAIL: %s", cfg.AdminEmail)
	}
	if generated != "" {
		bootstrapPath := filepath.Join(cfg.DataDir, "bootstrap-admin.txt")
		contents := fmt.Sprintf("ZentProxy bootstrap administrator\nE-mail: %s\nPassword: %s\n\nThis file is deleted after the first successful login.\n", cfg.AdminEmail, generated)
		if err := os.WriteFile(bootstrapPath, []byte(contents), 0600); err != nil {
			log.Fatalf("admin bootstrap: write %s: %v", bootstrapPath, err)
		}
		if err := os.Chmod(bootstrapPath, 0600); err != nil {
			log.Fatalf("admin bootstrap: protect %s: %v", bootstrapPath, err)
		}
		log.Printf("BOOTSTRAP ADMIN EMAIL: %s", cfg.AdminEmail)
		log.Printf("BOOTSTRAP ADMIN PASSWORD: %s", generated)
		log.Printf("Bootstrap credentials were also written to %s and will be deleted after the first successful login.", bootstrapPath)
	}

	proxyManager := proxy.NewManager(store, cfg.DataDir)
	if err := proxyManager.Apply(); err != nil {
		log.Fatalf("initial proxy configuration: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	providerManager := providers.New(store, cfg.ProviderRefreshEvery, proxyManager.Apply)
	providerManager.Start(ctx)
	certManager := certificates.New(store, cfg.DataDir, proxyManager.Apply)
	certManager.Start(ctx)
	analytics.New(store, cfg.DataDir, cfg.RawRetentionDays, cfg.AnalyticsLogMaxBytes, proxyManager.ReopenLogs).Start(ctx)

	zentLoopMonitor := zentloop.NewMonitor(store)
	zentLoopMonitor.Start(ctx)

	apiServer := api.New(cfg, store, proxyManager, providerManager, certManager, zentLoopMonitor)
	adminHTTP := &http.Server{Addr: fmt.Sprintf(":%d", cfg.AdminPort), Handler: apiServer.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second}
	integrationHTTP := &http.Server{Addr: "127.0.0.1:18081", Handler: zentloop.New(store, zentLoopMonitor), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}

	errCh := make(chan error, 2)
	go func() {
		log.Printf("ZentProxy %s admin API listening on :%d", cfg.Version, cfg.AdminPort)
		errCh <- adminHTTP.ListenAndServe()
	}()
	go func() {
		log.Printf("ZentLoop integration bridge listening internally on 127.0.0.1:18081")
		errCh <- integrationHTTP.ListenAndServe()
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case s := <-sig:
		log.Printf("received %s, shutting down", s)
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP server stopped: %v", err)
		}
	}
	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer shutdownCancel()
	_ = adminHTTP.Shutdown(shutdownCtx)
	_ = integrationHTTP.Shutdown(shutdownCtx)
}
