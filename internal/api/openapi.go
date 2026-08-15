package api

import (
	_ "embed"
	"net/http"
)

//go:embed openapi.yaml
var openAPISpec []byte

func (s *Server) openapi(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "inline; filename=\"openapi.yaml\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(openAPISpec)
}
