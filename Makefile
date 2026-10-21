.PHONY: all build build-static build-shared test clean fmt lint check tools help release release-check

# Paths
LIBPATH := ./lib
INCPATH := ./include
LIBNAME_STATIC := libecapture_decryptor.a

# Detect OS for shared library extension
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	LIBNAME_SHARED := libecapture_decryptor.dylib
else
	LIBNAME_SHARED := libecapture_decryptor.so
endif

HEADER := libecapture_decryptor.h
PKG_PATH := github.com/gojue/ecapture_decryptor

# Default target
all: build-static

# Build static library (for C/C++ programs)
build-static:
	@mkdir -p $(LIBPATH)
	@mkdir -p $(INCPATH)
	@echo "Building static library..."
	@cd capi && CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -buildmode=c-archive -o ../$(LIBPATH)/$(LIBNAME_STATIC) .
	@mv capi/$(HEADER) $(INCPATH)/$(HEADER) 2>/dev/null || mv $(LIBPATH)/$(HEADER) $(INCPATH)/$(HEADER) 2>/dev/null || true
	@echo "✓ Static library: $(LIBPATH)/$(LIBNAME_STATIC)"
	@echo "✓ Header file: $(INCPATH)/$(HEADER)"
	@ls -lh $(LIBPATH)/$(LIBNAME_STATIC)

# Build shared library (for dynamic linking)
build-shared:
	@mkdir -p $(LIBPATH)
	@mkdir -p $(INCPATH)
	@echo "Building shared library..."
	@cd capi && CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -buildmode=c-shared -o ../$(LIBPATH)/$(LIBNAME_SHARED) .
	@mv capi/$(HEADER) $(INCPATH)/$(HEADER) 2>/dev/null || mv $(LIBPATH)/$(HEADER) $(INCPATH)/$(HEADER) 2>/dev/null || true
	@echo "✓ Shared library: $(LIBPATH)/$(LIBNAME_SHARED)"
	@echo "✓ Header file: $(INCPATH)/$(HEADER)"
	@ls -lh $(LIBPATH)/$(LIBNAME_SHARED)

# Build both static and shared libraries
build: build-static build-shared

# Run unit tests
test:
	@echo "Running unit tests..."
	go test -v ./...

# Clean built artifacts
clean:
	@echo "Cleaning library artifacts..."
	rm -rf $(LIBPATH)/ $(INCPATH)/
	go clean
	@echo "✓ Cleaned"

# Code formatting
fmt:
	@echo "Formatting Go code..."
	go fmt ./...
	goimports -w .
	@echo "✓ Code formatted"

# Static analysis
lint:
	@echo "Running linter..."
	golangci-lint run ./...
	@echo "✓ Linting completed"

# Format check (for CI - doesn't modify files)
check:
	@echo "Checking code format..."
	gofmt -l -d .
	goimports -l -d .
	golangci-lint run ./...
	@echo "✓ Check completed"

# Install development tools
tools:
	@echo "Installing development tools..."
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@echo "✓ Tools installed"

# Release management
release:
	@if [ -z "$(VERSION)" ]; then \
		echo "Error: VERSION is required"; \
		echo "Usage: make release VERSION=v2.0.0"; \
		exit 1; \
	fi
	@echo "Creating release $(VERSION)..."
	./scripts/release.sh $(VERSION)

release-check:
	@echo "Pre-release checklist:"
	@echo "  1. Update version in capi/main.go"
	@echo "  2. Update CHANGELOG.md"
	@echo "  3. Run: make test"
	@echo "  4. Run: make fmt && make lint"
	@echo "  5. Commit all changes"
	@echo "  6. Run: make release VERSION=vX.Y.Z"
	@echo "  7. Test the release package"
	@echo "  8. Create git tag: git tag vX.Y.Z"
	@echo "  9. Push tag: git push origin vX.Y.Z"
	@echo "  10. GitHub Actions will create the release automatically"

# Help
help:
	@echo "ecapture_decryptor Makefile"
	@echo ""
	@echo "Library Build Targets:"
	@echo "  all (default)    - Build static library"
	@echo "  build-static     - Build static library (.a)"
	@echo "  build-shared     - Build shared library (.so/.dylib)"
	@echo "  build            - Build both static and shared libraries"
	@echo ""
	@echo "Testing:"
	@echo "  test             - Run unit tests"
	@echo ""
	@echo "Code Quality:"
	@echo "  fmt              - Format code"
	@echo "  lint             - Run linter"
	@echo "  check            - Check code format (CI mode)"
	@echo ""
	@echo "Release Management:"
	@echo "  release          - Build release package (requires VERSION=vX.Y.Z)"
	@echo "  release-check    - Show pre-release checklist"
	@echo ""
	@echo "Maintenance:"
	@echo "  clean            - Remove built artifacts"
	@echo "  tools            - Install development tools"
	@echo "  help             - Show this help"
	@echo ""
	@echo "Examples:"
	@echo "  make release VERSION=v2.0.0"
	@echo ""
	@echo "For building and testing examples, see:"
	@echo "  cd examples && make help"

