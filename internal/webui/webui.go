package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed assets/*
var assets embed.FS

func Handler() http.Handler {
	sub, _ := fs.Sub(assets, "assets")
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "." || p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(sub, p); err != nil {
			r2 := r.Clone(r.Context())
			r2.URL.Path = "/index.html"
			files.ServeHTTP(w, r2)
			return
		}
		files.ServeHTTP(w, r)
	})
}
