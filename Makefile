.PHONY: build test test-cover lint clean run

# Binary name
BINARY=rampart-agent
VERSION?=0.1.0

# Build flags
LDFLAGS=-ldflags "-X main.version=$(VERSION)"

# Build the binary
build:
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/agent

# Run tests
test:
	go test -v ./...

# Run tests with coverage
test-cover:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Run tests in watch mode (requires gotestsum)
test-watch:
	gotestsum --watch

# Lint (requires golangci-lint)
lint:
	golangci-lint run

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

# Run the agent locally
run: build
	./bin/$(BINARY)

# Install dependencies
deps:
	go mod download
	go mod tidy

# Build Docker image
docker-build:
	docker build -t rampart-agent:$(VERSION) .

# Run in Docker
docker-run:
	docker run --rm \
		-v /var/run/docker.sock:/var/run/docker.sock:ro \
		-v $(PWD)/config.yaml:/etc/rampart/agent.yaml:ro \
		rampart-agent:$(VERSION)
