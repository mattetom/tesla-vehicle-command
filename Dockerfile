# ---- Build stage ----
FROM golang:1.23.0 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build proxy binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -o /tesla-http-proxy ./cmd/tesla-http-proxy


# ---- Runtime stage ----
FROM gcr.io/distroless/base-debian12:nonroot

WORKDIR /

# Copy binary
COPY --from=builder /tesla-http-proxy /usr/local/bin/tesla-http-proxy

# No /data needed anymore
ENTRYPOINT ["/usr/local/bin/tesla-http-proxy"]
