#!/bin/sh
set -eu

DATA_DIR="${ZENTPROXY_DATA_DIR:-/data}"
SYSTEM_DIR="$DATA_DIR/nginx/system"
RUNTIME_PREFIX="$DATA_DIR/nginx/runtime"
mkdir -p "$DATA_DIR" "$DATA_DIR/nginx/hosts" "$SYSTEM_DIR" "$RUNTIME_PREFIX/logs" "$DATA_DIR/nginx/tmp/client_body" "$DATA_DIR/nginx/tmp/proxy" "$DATA_DIR/nginx/tmp/fastcgi" "$DATA_DIR/nginx/tmp/uwsgi" "$DATA_DIR/nginx/tmp/scgi" "$DATA_DIR/logs" "$DATA_DIR/cache" "$DATA_DIR/certs/default" "$DATA_DIR/acme" "$DATA_DIR/acme-webroot/.well-known/acme-challenge"

# A container restart cannot retain an OpenResty process, but /data is persistent.
# Generated nginx.conf is runtime state too: remove it before starting the control
# plane so the readiness wait below cannot be satisfied by a stale config from a
# previous image/version. The control plane recreates it atomically from SQLite.
rm -f "$SYSTEM_DIR/openresty.pid" "$SYSTEM_DIR/openresty-test.pid" "$SYSTEM_DIR/nginx-test.conf" "$DATA_DIR/nginx/nginx.conf"

if [ ! -s "$DATA_DIR/certs/default/fullchain.pem" ] || [ ! -s "$DATA_DIR/certs/default/privkey.pem" ]; then
  openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
    -subj "/CN=ZentProxy Catch-All" \
    -keyout "$DATA_DIR/certs/default/privkey.pem" \
    -out "$DATA_DIR/certs/default/fullchain.pem" >/dev/null 2>&1
  chmod 600 "$DATA_DIR/certs/default/privkey.pem"
fi
chown -R zentproxy:zentproxy "$DATA_DIR"

su-exec zentproxy:zentproxy /usr/local/bin/zentproxy &
APP_PID=$!
PROXY_PID=""

cleanup() {
  [ -z "$PROXY_PID" ] || kill "$PROXY_PID" 2>/dev/null || true
  kill "$APP_PID" 2>/dev/null || true
}
trap cleanup INT TERM EXIT

i=0
while [ ! -s "$DATA_DIR/nginx/nginx.conf" ]; do
  i=$((i+1))
  if [ "$i" -gt 100 ]; then
    echo "ZentProxy: generated proxy configuration was not created" >&2
    exit 1
  fi
  if ! kill -0 "$APP_PID" 2>/dev/null; then
    echo "ZentProxy: control plane exited during startup" >&2
    exit 1
  fi
  sleep 0.1
done

su-exec zentproxy:zentproxy /usr/local/openresty/bin/openresty -p "$RUNTIME_PREFIX/" -e stderr -g 'daemon off;' -c "$DATA_DIR/nginx/nginx.conf" &
PROXY_PID=$!
wait "$PROXY_PID"
STATUS=$?
kill "$APP_PID" 2>/dev/null || true
wait "$APP_PID" 2>/dev/null || true
exit "$STATUS"
