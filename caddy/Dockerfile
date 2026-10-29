# xcaddy is needed for the rate_limit module (not in the official build).
FROM caddy:2-builder AS builder
# proxy.golang.org is unreachable in CN networks; override with
# --build-arg GOPROXY=direct if you build elsewhere.
ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}
RUN xcaddy build --with github.com/mholt/caddy-ratelimit

FROM caddy:2-alpine
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
# Bootstrap config only. The panel replaces the whole config at runtime through
# the admin API, so nothing here (except the admin listener) survives startup.
COPY Caddyfile /etc/caddy/Caddyfile
