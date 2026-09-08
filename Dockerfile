FROM golang:1.20-alpine AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/shorturl .

FROM alpine:3.20

RUN addgroup -S -g 10001 shorturl \
    && adduser -S -D -H -u 10001 -G shorturl shorturl

WORKDIR /app

COPY --from=build --chown=shorturl:shorturl /out/shorturl /app/shorturl

USER shorturl

ENV PORT=8080

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/url_api/healthz || exit 1

ENTRYPOINT ["/app/shorturl"]