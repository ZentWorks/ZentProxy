<p align="center">
  <img src="assets/zentproxy-logo.png" alt="ZentProxy" width="220">
</p>

# ZentProxy

ZentProxy is a Docker-based reverse proxy management solution with a web interface for managing proxy hosts, certificates, access rules, analytics and related services in one place.

> **Under Development**

## Features

- Central management of reverse proxy hosts
- TLS/SSL certificate management
- Access rules and host configuration
- Analytics and operational visibility
- Integrated API for automation and integrations
- Docker-first deployment
- Docker Compose support
- Suitable for Unraid deployments
- Integrated detailed documentation directly inside ZentProxy
- Multi-architecture container images for `linux/amd64` and `linux/arm64`

# Quick start

The production image is published to GitHub Container Registry:

```text
ghcr.io/zentworks/zentproxy:latest
```

Versioned releases can additionally be pulled by tag, for example:

```text
ghcr.io/zentworks/zentproxy:1.0.0
```

ZentProxy can be started with Docker Compose, directly with `docker run`, or through Unraid.

## 1. Docker Compose

Create a directory for ZentProxy:

```bash
mkdir zentproxy
cd zentproxy
```

Create a `.env` file:

```dotenv
TZ=Europe/Berlin

ZENTPROXY_ADMIN_EMAIL=admin@example.com
ZENTPROXY_ADMIN_PASSWORD=
ZENTPROXY_ADMIN_PORT=8080

ZENTPROXY_DATA_DIR=/data
ZENTPROXY_ANALYTICS_RETENTION_DAYS=7
ZENTPROXY_ANALYTICS_IP_MODE=anonymized
ZENTPROXY_ANALYTICS_LOG_MAX_MB=64
ZENTPROXY_PROVIDER_REFRESH_HOURS=6

ZENTPROXY_ADMIN_COOKIE_SECURE=false

# Optional:
# ZENTPROXY_TRUSTED_TRANSPORT_HOPS=192.168.65.1
```

Change at least:

```dotenv
ZENTPROXY_ADMIN_EMAIL=you@example.com
```

For a fresh installation, `ZENTPROXY_ADMIN_PASSWORD` may be left empty. ZentProxy will then generate a random bootstrap password and print it once to the container log.

Create `docker-compose.yml`:

```yaml
services:
  zentproxy:
    image: ghcr.io/zentworks/zentproxy:latest
    container_name: zentproxy
    restart: unless-stopped

    env_file:
      - .env

    ports:
      - "80:80"
      - "443:443"
      - "${ZENTPROXY_ADMIN_PORT:-8080}:${ZENTPROXY_ADMIN_PORT:-8080}"

    volumes:
      - ./data:${ZENTPROXY_DATA_DIR:-/data}
```

Start ZentProxy:

```bash
docker compose up -d
```

Follow the startup log:

```bash
docker compose logs -f zentproxy
```

If `ZENTPROXY_ADMIN_PASSWORD` was left empty, use the generated bootstrap password shown in the startup log.

To stop ZentProxy:

```bash
docker compose down
```

The persistent data remains in:

```text
./data
```

## 2. Docker CLI

Docker Compose is not required. The same container can be started directly with Docker.

### Using an `.env` file

Create `.env` as shown above and run:

```bash
docker run -d \
  --name zentproxy \
  --restart unless-stopped \
  --env-file .env \
  -p 80:80 \
  -p 443:443 \
  -p 8080:8080 \
  -v "$(pwd)/data:/data" \
  ghcr.io/zentworks/zentproxy:latest
```

View the log:

```bash
docker logs -f zentproxy
```

### Passing variables directly

Environment variables can also be supplied directly with `-e`:

```bash
docker run -d \
  --name zentproxy \
  --restart unless-stopped \
  -p 80:80 \
  -p 443:443 \
  -p 8080:8080 \
  -v "$(pwd)/data:/data" \
  -e TZ=Europe/Berlin \
  -e ZENTPROXY_ADMIN_EMAIL=admin@example.com \
  -e ZENTPROXY_ADMIN_PASSWORD= \
  -e ZENTPROXY_ADMIN_PORT=8080 \
  -e ZENTPROXY_DATA_DIR=/data \
  -e ZENTPROXY_ANALYTICS_RETENTION_DAYS=7 \
  -e ZENTPROXY_ANALYTICS_IP_MODE=anonymized \
  -e ZENTPROXY_ANALYTICS_LOG_MAX_MB=64 \
  -e ZENTPROXY_PROVIDER_REFRESH_HOURS=6 \
  -e ZENTPROXY_ADMIN_COOKIE_SECURE=false \
  ghcr.io/zentworks/zentproxy:latest
```

Replace `admin@example.com` with the real administrator e-mail address before starting the container.

If the admin port is changed, the Docker port mapping must be changed as well. For example:

```bash
-e ZENTPROXY_ADMIN_PORT=9090 \
-p 9090:9090
```

## Environment variables

The public repository contains an `.env.example` that can be used as a starting point:

```bash
cp .env.example .env
```

Then edit `.env` before starting ZentProxy.

| Variable | Default / Example | Required | Description |
|---|---|---:|---|
| `TZ` | `Europe/Berlin` | No | Container timezone. |
| `ZENTPROXY_ADMIN_EMAIL` | `admin@example.com` | **Yes for a fresh installation** | Initial administrator e-mail address. Replace the example value. |
| `ZENTPROXY_ADMIN_PASSWORD` | empty | No | Initial administrator password. If empty, ZentProxy generates a random bootstrap password and prints it once to the container log. |
| `ZENTPROXY_ADMIN_PORT` | `8080` | No | Port used by the ZentProxy administration interface. |
| `ZENTPROXY_DATA_DIR` | `/data` | No | Persistent data directory inside the container. |
| `ZENTPROXY_ANALYTICS_RETENTION_DAYS` | `7` | No | Analytics retention in days. Effective range is 1–30; larger values are capped at 30. |
| `ZENTPROXY_ANALYTICS_IP_MODE` | `anonymized` | No | Client IP storage: `full`, `anonymized`, or `disabled`. |
| `ZENTPROXY_ANALYTICS_LOG_MAX_MB` | `64` | No | Maximum size in MB of the temporary JSON analytics access-log spool. Processed data is stored in SQLite. |
| `ZENTPROXY_PROVIDER_REFRESH_HOURS` | `6` | No | Refresh interval for provider-related data, in hours. |
| `ZENTPROXY_ADMIN_COOKIE_SECURE` | `false` | No | Controls the Secure attribute of the administrator session cookie. Enable it when the administration interface is served exclusively through HTTPS. |
| `ZENTPROXY_TRUSTED_TRANSPORT_HOPS` | unset | No | Optional comma-separated list of exact container/NAT transport hops when automatic detection is insufficient. |

Example for Docker Desktop ingress NAT:

```dotenv
ZENTPROXY_TRUSTED_TRANSPORT_HOPS=192.168.65.1
```

Do not set trusted transport hops unless they are actually required for the deployment environment.

---

# Unraid

ZentProxy uses the same production image on Unraid:

```text
ghcr.io/zentworks/zentproxy:latest
```

Create a new Docker container in Unraid and use the image above.

Configure the container with the same values used for Docker or Docker Compose:

### Ports

```text
80
443
8080
```

`8080` is the default administration port and can be changed through `ZENTPROXY_ADMIN_PORT`.

### Persistent storage

Map a persistent host/appdata path to:

```text
/data
```

Example:

```text
/mnt/user/appdata/zentproxy  ->  /data
```

### Environment variables

Add the required and optional `ZENTPROXY_*` variables from the environment-variable table above through the Unraid Docker configuration.

A dedicated Unraid Community Applications template can be provided later without requiring a separate ZentProxy image.

---

# Administration

With the default configuration, the administration interface uses:

```text
http://<docker-host>:8080
```

If `ZENTPROXY_ADMIN_PORT` is changed, use the configured port instead.

For production deployments, use appropriate HTTPS and network-access protection for administrative access.

---

# API

ZentProxy includes an API for automation and integrations.

Detailed API documentation, available endpoints, authentication information and examples are documented directly inside ZentProxy so that the documentation remains aligned with the installed version.

The GitHub README intentionally provides only the deployment overview rather than duplicating the complete API reference.

---

# Documentation

Detailed documentation is integrated into ZentProxy and is intended to be the primary reference for:

- proxy configuration
- certificates
- access rules
- analytics
- API usage
- administration
- operational settings
- troubleshooting

This GitHub repository focuses on:

- installation
- Docker deployment
- Docker Compose
- Unraid
- container images
- environment variables
- updates
- release information
- basic feature overview

---

# Updating

## Docker Compose

Pull the current image:

```bash
docker compose pull
```

Recreate the container:

```bash
docker compose up -d
```

## Docker CLI

Pull the current image:

```bash
docker pull ghcr.io/zentworks/zentproxy:latest
```

Stop and remove the old container:

```bash
docker stop zentproxy
docker rm zentproxy
```

Then start it again with the same `docker run` configuration.

Persistent data is retained as long as the mapped data directory is not removed.

Before major updates, review the release notes for configuration changes or migration requirements.

---

# Data and backups

Persistent ZentProxy data must be stored outside the writable container layer.

The default container data directory is:

```text
/data
```

With the Docker Compose example above it is stored on the host in:

```text
./data
```

Back up the persistent data directory before major updates.

Do not rely on the container filesystem itself for persistent application data.

---

# Security

For production operation:

- change the administrator e-mail address before the first start
- use a strong administrator password or securely store the generated bootstrap password
- do not commit `.env` files or secrets
- keep persistent data backed up
- restrict access to the administration interface
- use HTTPS for administrative access where appropriate
- set `ZENTPROXY_ADMIN_COOKIE_SECURE=true` when the administration interface is exclusively accessed over HTTPS
- configure trusted transport hops only when required by the actual network topology

---

# License

See [LICENSE](LICENSE).
