FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /shim ./cmd/shim

# Runtime stage
FROM alpine:3.19

# Add ca-certificates for HTTPS calls to AIDR API
RUN apk --no-cache add ca-certificates

# Copy binary from builder
COPY --from=builder /shim /shim

# Run as non-root user
RUN adduser -D -g '' appuser
USER appuser

# Expose gRPC and health check ports
EXPOSE 8080 8081

CMD ["/shim"]
