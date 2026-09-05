#!/bin/sh
set -eu

DATA_DIR="${ZENTPROXY_DATA_DIR:-/data}"
RUNTIME_DIR="${ZENTPROXY_RUNTIME_DIR:-/tmp/zentproxy}"
SYSTEM_DIR="$DATA_DIR/nginx/system"
RUNTIME_PREFIX="$DATA_DIR/nginx/runtime"
READY_FILE="$SYSTEM_DIR/proxy-config.ready"
mkdir -p "$DATA_DIR" "$DATA_DIR/nginx/hosts" "$SYSTEM_DIR" "$RUNTIME_PREFIX/logs" \
  "$RUNTIME_DIR/nginx/tmp/client_body" "$RUNTIME_DIR/nginx/tmp/proxy" "$RUNTIME_DIR/nginx/tmp/fastcgi" \
  "$RUNTIME_DIR/nginx/tmp/uwsgi" "$RUNTIME_DIR/nginx/tmp/scgi" "$RUNTIME_DIR/analytics" "$RUNTIME_DIR/cache" \
  "$DATA_DIR/logs" "$DATA_DIR/certs/default" "$DATA_DIR/acme" "$DATA_DIR/acme-webroot/.well-known/acme-challenge"

# Raise the inherited soft open-file limit to the container hard limit whenever
# the runtime allows it. The Go control plane reads the resulting real limit and
# sizes worker_connections/keepalive pools below it instead of assuming a fixed
# capacity. Compose/Unraid templates provide a 65535 hard limit; custom docker
# runs without that setting still degrade safely to their actual limit.
SOFT_NOFILE="$(ulimit -Sn 2>/dev/null || ulimit -n 2>/dev/null || echo 1024)"
HARD_NOFILE="$(ulimit -Hn 2>/dev/null || echo "$SOFT_NOFILE")"
case "$HARD_NOFILE" in
  ''|*[!0-9]*) ;;
  *)
    case "$SOFT_NOFILE" in
      ''|*[!0-9]*) ;;
      *)
        if [ "$SOFT_NOFILE" -lt "$HARD_NOFILE" ]; then
          ulimit -S -n "$HARD_NOFILE" 2>/dev/null || true
        fi
        ;;
    esac
    ;;
esac
EFFECTIVE_NOFILE="$(ulimit -Sn 2>/dev/null || ulimit -n 2>/dev/null || echo unknown)"
echo "ZentProxy: effective open-file limit: $EFFECTIVE_NOFILE"
case "$EFFECTIVE_NOFILE" in
  ''|*[!0-9]*) ;;
  *)
    if [ "$EFFECTIVE_NOFILE" -lt 8192 ]; then
      echo "ZentProxy: WARNING: low open-file limit ($EFFECTIVE_NOFILE); recreate the container with --ulimit nofile=65535:65535 for production burst/WebSocket traffic" >&2
    fi
    ;;
esac

# A container restart cannot retain an OpenResty process, but /data is persistent.
# Keep the last known-good nginx.conf for recovery, but never use mere file
# existence as the startup signal. The control plane writes READY_FILE only after
# the current database state has produced a validated current/degraded/fallback
# configuration. This prevents OpenResty from racing ahead with yesterday's file.
rm -f "$SYSTEM_DIR/openresty.pid" "$SYSTEM_DIR/openresty-test.pid" "$SYSTEM_DIR/nginx-test.conf" "$READY_FILE" "$READY_FILE.tmp"

if [ ! -s "$DATA_DIR/certs/default/fullchain.pem" ] || [ ! -s "$DATA_DIR/certs/default/privkey.pem" ]; then
  openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
    -subj "/CN=ZentProxy Catch-All" \
    -keyout "$DATA_DIR/certs/default/privkey.pem" \
    -out "$DATA_DIR/certs/default/fullchain.pem" >/dev/null 2>&1
  chmod 600 "$DATA_DIR/certs/default/privkey.pem"
fi
chown -R zentproxy:zentproxy "$DATA_DIR" "$RUNTIME_DIR"

su-exec zentproxy:zentproxy /usr/local/bin/zentproxy &
APP_PID=$!
PROXY_PID=""

cleanup() {
  [ -z "$PROXY_PID" ] || kill "$PROXY_PID" 2>/dev/null || true
  kill "$APP_PID" 2>/dev/null || true
}
trap cleanup INT TERM EXIT

# Wait for the control plane's explicit readiness marker, not nginx.conf itself.
# If proxy configuration cannot become ready, keep the control plane alive so
# /api and the WebUI remain available for repair instead of restart-looping.
i=0
while [ ! -s "$READY_FILE" ]; do
  i=$((i+1))
  if ! kill -0 "$APP_PID" 2>/dev/null; then
    echo "ZentProxy: control plane exited during startup" >&2
    wait "$APP_PID" || true
    exit 1
  fi
  if [ $((i % 100)) -eq 0 ]; then
    echo "ZentProxy: waiting for validated proxy configuration; admin API remains available" >&2
  fi
  sleep 0.1
done

su-exec zentproxy:zentproxy /usr/local/openresty/bin/openresty -p "$RUNTIME_PREFIX/" -e stderr -g 'daemon off;' -c "$DATA_DIR/nginx/nginx.conf" &
PROXY_PID=$!

# The control plane and data plane are one service from Docker's perspective.
# If either process dies, terminate the other and let the container restart
# policy recover the complete service instead of leaving a half-alive proxy.
# Polling is deliberate here so the entrypoint stays portable across /bin/sh
# implementations instead of depending on the non-POSIX `wait -n` extension.
while :; do
  if ! kill -0 "$APP_PID" 2>/dev/null; then
    set +e
    wait "$APP_PID"
    STATUS=$?
    set -e
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
    exit "$STATUS"
  fi
  if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    set +e
    wait "$PROXY_PID"
    STATUS=$?
    set -e
    kill "$APP_PID" 2>/dev/null || true
    wait "$APP_PID" 2>/dev/null || true
    exit "$STATUS"
  fi
  sleep 0.5
done
