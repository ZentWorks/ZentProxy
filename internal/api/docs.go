package api

import "net/http"

const apiDocsHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark light">
  <title>ZentProxy Developer API</title>
</head>
<body>
  <div id="app"></div>
  <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference@1.63.0"></script>
  <script>
    Scalar.createApiReference('#app', {
      url: '/api/v1/openapi.yaml',
      pageTitle: 'ZentProxy Developer API',
      theme: 'default',
      layout: 'modern',
      darkMode: true,
      hideClientButton: true,
      hideTestRequestButton: false,
      showToolbar: 'never',
      agent: { disabled: true },
      showSidebar: true
    })
  </script>
</body>
</html>`

func (s *Server) apiDocs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(apiDocsHTML))
}
