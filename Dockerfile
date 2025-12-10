# ---- Build stage ----
FROM golang:1.23.0 AS build

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN mkdir build
RUN go build -o ./build/tesla-http-proxy ./cmd/tesla-http-proxy

# ---- Runtime stage ----
FROM debian:bookworm-slim AS runtime

# Install minimal dependencies (ca-certificates)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from build stage
COPY --from=build /app/build/tesla-http-proxy /usr/local/bin/tesla-http-proxy

# Copy entrypoint script and make executable
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Non-root user for security
RUN useradd -m appuser
USER appuser

ENTRYPOINT ["/entrypoint.sh"]
