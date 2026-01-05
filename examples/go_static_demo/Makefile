# Makefile for Go Static Demo
# This demonstrates the same workflow as C demo but using Go API directly
# Note: Direct CGO linking of Go c-archive into Go program causes symbol conflicts,
# so we use the Go API instead while maintaining the same interface and behavior.

# Binary name
BINDIR := ../../bin
BINNAME := go_static_decryptor

# Test data
TESTDATA := ../../test/testdata

.PHONY: all build test clean help

all: build

# Build the Go program
build:
	@mkdir -p $(BINDIR)
	@echo "Building Go static demo program..."
	@echo "  Note: Using Go API directly (equivalent to C API functionality)"
	go build -o $(BINDIR)/$(BINNAME) .
	@echo "✓ Built: $(BINDIR)/$(BINNAME)"
	@ls -lh $(BINDIR)/$(BINNAME)

# Test with sample data
test: build
	@echo "Testing go_static_decryptor..."
	@if [ -f "$(TESTDATA)/all_clients.pcap" ] && [ -f "$(TESTDATA)/all_clients_sslkey.log" ]; then \
		$(BINDIR)/$(BINNAME) \
			-pcap $(TESTDATA)/all_clients.pcap \
			-keylog $(TESTDATA)/all_clients_sslkey.log \
			-output output_go_static.json && \
		echo "" && \
		echo "✓ Test passed!" && \
		echo "  Output file: output_go_static.json"; \
	else \
		echo "⚠ Test data not found, skipping test"; \
		echo "  Expected: $(TESTDATA)/all_clients.pcap"; \
		echo "  Expected: $(TESTDATA)/all_clients_sslkey.log"; \
	fi

# Show version
version: build
	@$(BINDIR)/$(BINNAME) -version

# Clean built files
clean:
	@echo "Cleaning go_static_demo..."
	@rm -f $(BINDIR)/$(BINNAME)
	@rm -f output_go_static.json
	@echo "✓ Cleaned"

# Help
help:
	@echo "Go Static Demo Makefile Targets:"
	@echo "  all (default) - Build the Go demo program"
	@echo "  build         - Build the program"
	@echo "  test          - Build and test with sample data"
	@echo "  version       - Show library version"
	@echo "  clean         - Remove built binaries"
	@echo "  help          - Show this help message"
	@echo ""
	@echo "This demo provides the same functionality as the C demo"
	@echo "but uses the Go API directly to avoid CGO symbol conflicts."
	@echo ""
	@echo "Usage:"
	@echo "  $(BINDIR)/$(BINNAME) -pcap <file> -keylog <file> [-output <file>]"



