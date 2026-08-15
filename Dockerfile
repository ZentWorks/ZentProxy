FROM golang:1.26.6-alpine3.23 AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates git build-base sqlite-dev
COPY go.mod ./
COPY . .
ARG VERSION=dev
ARG COMMIT=unknown
RUN CGO_ENABLED=1 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o /out/zentproxy ./cmd/zentproxy && \
    CGO_ENABLED=0 GOBIN=/out go install github.com/go-acme/lego/v5@v5.3.1

FROM openresty/openresty:1.31.1.1-2-alpine
ARG SOURCE_URL=https://github.com/zentproxy/zentproxy
LABEL org.opencontainers.image.title="ZentProxy" \
      org.opencontainers.image.description="Lightweight reverse proxy control plane with analytics and integrations" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      net.unraid.docker.webui="http://[IP]:[PORT:8080]/"
RUN apk add --no-cache ca-certificates curl openssl tzdata su-exec libcap sqlite-libs apache2-utils && \
    addgroup -S zentproxy && adduser -S -D -H -G zentproxy zentproxy
COPY --from=build /out/zentproxy /usr/local/bin/zentproxy
COPY --from=build /out/lego /usr/local/bin/lego
COPY docker/entrypoint.sh /usr/local/bin/zentproxy-entrypoint
COPY docker/healthcheck.sh /usr/local/bin/zentproxy-healthcheck
RUN chmod +x /usr/local/bin/zentproxy-entrypoint /usr/local/bin/zentproxy-healthcheck && \
    setcap cap_net_bind_service=+ep /usr/local/openresty/nginx/sbin/nginx
VOLUME ["/data"]
EXPOSE 80/tcp 443/tcp 443/udp 8080/tcp
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["zentproxy-healthcheck"]
ENTRYPOINT ["zentproxy-entrypoint"]
