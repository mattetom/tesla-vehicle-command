# ---- Build stage ----
FROM golang:1.23.0 AS build

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN mkdir build
RUN go build -o ./build/tesla-http-proxy ./cmd/tesla-http-proxy

# Copy entrypoint here (IN BUILD STAGE) and make it executable
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh


# ---- Runtime stage ----
FROM gcr.io/distroless/base-debian12:nonroot AS runtime

WORKDIR /app

# Copy binary
COPY --from=build /app/build/tesla-http-proxy /usr/local/bin/tesla-http-proxy

# Copy entrypoint ALREADY EXECUTABLE
COPY --from=build /entrypoint.sh /entrypoint.sh

USER nonroot
ENTRYPOINT ["/entrypoint.sh"]
