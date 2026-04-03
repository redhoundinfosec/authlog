BINARY      := authlog
BIN_DIR     := bin
CMD_PATH    := ./cmd/authlog
VERSION     := $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0")
LDFLAGS     := -ldflags "-X github.com/redhoundinfosec/authlog/internal/output.Version=$(VERSION) -s -w"
GO          := go
GOFLAGS     :=

.PHONY: all build test test-v lint clean release help

all: build

## build: Compile the authlog binary to ./bin/authlog
build:
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BIN_DIR)/$(BINARY) $(CMD_PATH)
	@echo "Built $(BIN_DIR)/$(BINARY)"

## test: Run all unit tests
test:
	$(GO) test ./... -count=1

## test-v: Run all unit tests with verbose output
test-v:
	$(GO) test ./... -v -count=1

## test-race: Run tests with race detector
test-race:
	$(GO) test -race ./... -count=1

## lint: Run golangci-lint (must be installed)
lint:
	golangci-lint run ./...

## vet: Run go vet
vet:
	$(GO) vet ./...

## tidy: Run go mod tidy
tidy:
	$(GO) mod tidy

## clean: Remove build artifacts
clean:
	rm -rf $(BIN_DIR)
	$(GO) clean -testcache

## demo-linux: Run a demo against the Linux sample log
demo-linux: build
	./$(BIN_DIR)/$(BINARY) analyze examples/linux-auth.log --no-color

## demo-windows: Run a demo against the Windows XML sample
demo-windows: build
	./$(BIN_DIR)/$(BINARY) analyze examples/windows-security.xml --no-color

## demo-json: Run a demo producing JSON output
demo-json: build
	./$(BIN_DIR)/$(BINARY) analyze examples/linux-auth.log --format json

## release: Cross-compile for Linux, macOS, and Windows (amd64 + arm64)
release: tidy
	@mkdir -p dist
	GOOS=linux   GOARCH=amd64  $(GO) build $(LDFLAGS) -o dist/$(BINARY)-linux-amd64    $(CMD_PATH)
	GOOS=linux   GOARCH=arm64  $(GO) build $(LDFLAGS) -o dist/$(BINARY)-linux-arm64    $(CMD_PATH)
	GOOS=darwin  GOARCH=amd64  $(GO) build $(LDFLAGS) -o dist/$(BINARY)-darwin-amd64   $(CMD_PATH)
	GOOS=darwin  GOARCH=arm64  $(GO) build $(LDFLAGS) -o dist/$(BINARY)-darwin-arm64   $(CMD_PATH)
	GOOS=windows GOARCH=amd64  $(GO) build $(LDFLAGS) -o dist/$(BINARY)-windows-amd64.exe $(CMD_PATH)
	@echo "Release binaries in dist/"

## help: Show this help message
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
