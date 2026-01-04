# Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Copy go mod files first for caching
COPY go.mod go.sum* ./

# Copy source code (needed for go mod tidy)
COPY . .

# Generate go.sum and download dependencies
RUN go mod tidy && go mod download

# Build the binary
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o rampart-agent \
    ./cmd/agent

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    # For network scanning
    iproute2 \
    net-tools

# Create non-root user
RUN addgroup -g 1000 rampart && \
    adduser -u 1000 -G rampart -s /bin/sh -D rampart

# Create directories
RUN mkdir -p /etc/rampart /var/lib/rampart/buffer && \
    chown -R rampart:rampart /etc/rampart /var/lib/rampart

# Copy binary from builder
COPY --from=builder /build/rampart-agent /usr/local/bin/rampart-agent

# Note: We run as root to access Docker socket and auth logs
# In production, consider using socket proxies or capabilities
USER root

ENTRYPOINT ["/usr/local/bin/rampart-agent"]
CMD ["--config", "/etc/rampart/agent.yaml"]
