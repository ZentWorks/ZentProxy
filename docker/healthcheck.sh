#!/bin/sh
set -eu
PORT="${ZENTPROXY_ADMIN_PORT:-8080}"
curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null
