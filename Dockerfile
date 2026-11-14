# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/poisonstop ./cmd/poisonstop \
 && mkdir -p /out/data

# Sidecar do modo transparente: precisa do iptables (roda com
# network_mode: host e NET_ADMIN). docker build --target netfilter
FROM alpine:3.24 AS netfilter
RUN apk add --no-cache iptables iptables-legacy
COPY --from=build /out/poisonstop /poisonstop
ENTRYPOINT ["/poisonstop", "netfilter"]

# Imagem final sem shell, sem root.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/poisonstop /poisonstop
COPY --from=build --chown=65532:65532 /out/data /data
USER 65532:65532
VOLUME ["/data"]
EXPOSE 3128 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s CMD ["/poisonstop", "healthcheck"]
ENTRYPOINT ["/poisonstop"]
