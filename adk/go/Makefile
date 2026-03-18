.PHONY: build test lint clean install fmt deps test-coverage test-short release check-release check

# ──────────────────────────────────────────────────────────
# ZAK Go SDK — github.com/securezeron/zeron-agent-development-kit/adk/go
# ──────────────────────────────────────────────────────────

VERSION     ?= 0.1.4
MODULE      := github.com/securezeron/zeron-agent-development-kit/adk/go
BINARY_NAME := zak
BUILD_DIR   := ./bin
GO_FILES    := $(shell find . -name '*.go' -not -path './vendor/*')
LDFLAGS     := -ldflags "-X github.com/securezeron/zeron-agent-development-kit/adk/go/internal/cli.Version=$(VERSION)"

# ──────── Build ────────

build:
	@echo "Building $(BINARY_NAME) v$(VERSION)..."
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/zak/

install:
	@echo "Installing $(BINARY_NAME) v$(VERSION)..."
	go install $(LDFLAGS) ./cmd/zak/

# ──────── Test ────────

test:
	@echo "Running tests..."
	go test -v -race -count=1 ./...

test-coverage:
	@echo "Running tests with coverage..."
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

test-short:
	@echo "Running short tests..."
	go test -short -count=1 ./...

# ──────── Quality ────────

lint:
	@echo "Running linter..."
	go vet ./...

fmt:
	@echo "Formatting..."
	gofmt -s -w $(GO_FILES)

check: lint test
	@echo "All checks passed."

# ──────── Dependencies ────────

deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

# ──────── Release ────────
# Go modules are published via git tags. The module lives at adk/go/ in the
# monorepo, so tags must include the path prefix.
#
# Usage:
#   make release                  # tags v0.1.4 (uses VERSION)
#   make release VERSION=0.2.0   # tags v0.2.0
#
# After tagging, push to GitHub and pkg.go.dev indexes it automatically:
#   git push origin adk/go/v$(VERSION)

release: check
	@echo ""
	@echo "=========================================="
	@echo "  ZAK Go SDK Release v$(VERSION)"
	@echo "=========================================="
	@echo ""
	@echo "Module:  $(MODULE)"
	@echo "Version: v$(VERSION)"
	@echo "Tag:     adk/go/v$(VERSION)"
	@echo ""
	@echo "Steps to publish:"
	@echo "  1. git tag -a adk/go/v$(VERSION) -m 'Release Go ADK v$(VERSION)'"
	@echo "  2. git push origin adk/go/v$(VERSION)"
	@echo "  3. GOPROXY=proxy.golang.org go list -m $(MODULE)@v$(VERSION)"
	@echo ""
	@echo "After push, the module will be indexed at:"
	@echo "  https://pkg.go.dev/$(MODULE)@v$(VERSION)"
	@echo ""

# Verify the module is correctly configured for publishing
check-release:
	@echo "Checking module configuration..."
	@echo "Module: $(MODULE)"
	@echo "Go version: $$(go version)"
	@echo ""
	@go mod verify
	@echo ""
	@echo "Packages:"
	@go list ./...
	@echo ""
	@echo "Module is ready for release."

# ──────── Clean ────────

clean:
	@echo "Cleaning..."
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html
