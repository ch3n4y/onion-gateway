# syntax=docker/dockerfile:1
FROM golang:1.23-alpine AS build
# proxy.golang.org is unreachable on some networks; override with
# --build-arg GOPROXY=direct if needed.
ARG GOPROXY=https://proxy.golang.org,direct
ARG VERSION=dev
ENV GOPROXY=${GOPROXY}
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/onion-gateway .

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/onion-gateway /usr/local/bin/onion-gateway
# Runs as root so it can read the tor control cookie (tor writes it 0600 into the
# shared volume).
USER root
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/onion-gateway"]
