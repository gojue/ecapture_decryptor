# Makefile for Examples
# Builds and tests all demo programs

.PHONY: all build test clean help build-go-demo build-c-demo build-go-static-demo test-go-demo test-c-demo test-go-static-demo

all: build

# Build all demos
build: build-go-demo build-c-demo build-go-static-demo

# Build individual demos
build-go-demo:
	@echo "Building Go demo..."
	@cd go_demo && $(MAKE) build
	@echo ""

build-c-demo:
	@echo "Building C demo..."
	@cd c_demo && $(MAKE) all
	@echo ""

build-go-static-demo:
	@echo "Building Go static demo..."
	@cd go_static_demo && $(MAKE) build
	@echo ""

# Test all demos
test: test-go-demo test-c-demo test-go-static-demo

# Test individual demos
test-go-demo:
	@echo "Testing Go demo..."
	@cd go_demo && $(MAKE) test
	@echo ""

test-c-demo:
	@echo "Testing C demo..."
	@cd c_demo && $(MAKE) test
	@echo ""

test-go-static-demo:
	@echo "Testing Go static demo..."
	@cd go_static_demo && $(MAKE) test
	@echo ""

# Clean all demos
clean:
	@echo "Cleaning all examples..."
	@cd go_demo && $(MAKE) clean 2>/dev/null || true
	@cd c_demo && $(MAKE) clean 2>/dev/null || true
	@cd go_static_demo && $(MAKE) clean 2>/dev/null || true
	@echo "✓ All examples cleaned"

# Help
help:
	@echo "Examples Makefile Targets:"
	@echo "  all (default)       - Build all demo programs"
	@echo "  build               - Build all demos"
	@echo "  build-go-demo       - Build Go demo only"
	@echo "  build-c-demo        - Build C demo only"
	@echo "  build-go-static-demo - Build Go static demo only"
	@echo "  test                - Test all demos"
	@echo "  test-go-demo        - Test Go demo only"
	@echo "  test-c-demo         - Test C demo only"
	@echo "  test-go-static-demo - Test Go static demo only"
	@echo "  clean               - Clean all demos"
	@echo "  help                - Show this help message"
	@echo ""
	@echo "Available demos:"
	@echo "  go_demo         - Go API usage example"
	@echo "  c_demo          - C static library usage example"
	@echo "  go_static_demo  - Go command-line tool (C demo equivalent)"

