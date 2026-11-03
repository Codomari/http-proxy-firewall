FROM golang:1.27-alpine AS build
WORKDIR /source
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY version.go VERSION ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /proxy-firewall ./cmd/proxy-firewall

FROM alpine:3.23
RUN apk add --no-cache ca-certificates && addgroup -S firewall && adduser -S -G firewall firewall && mkdir -p /app/files /app/.cache && chown -R firewall:firewall /app
WORKDIR /app
COPY --from=build /proxy-firewall /usr/local/bin/proxy-firewall
COPY LICENSE /usr/share/licenses/proxy-firewall/LICENSE
COPY proxy-firewall.default.yaml /app/proxy-firewall.default.yaml
USER firewall
ENV PF_LISTEN=0.0.0.0:8080 PF_TLS_LISTEN=0.0.0.0:8443 PF_PPROF_ADDRESS= PF_ADMIN_CREDS_FILE=
EXPOSE 8080 8443
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/proxy-firewall"]
