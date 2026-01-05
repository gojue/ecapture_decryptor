# Makefile for Go Demo
# This demonstrates using the Go API directly

# Binary name
BINDIR := ../../bin
BINNAME := ecapture_decryptor

# Test data
TESTDATA := ../../test/testdata

# Build flags for reducing binary size
LDFLAGS := -ldflags="-s -w"
BUILD_FLAGS := -trimpath $(LDFLAGS)

.PHONY: all build test clean help

all: build

# Build the Go demo program
build:
	@mkdir -p $(BINDIR)
	@echo "Building optimized Go demo binary (size-optimized)..."
	go build $(BUILD_FLAGS) -o $(BINDIR)/$(BINNAME) .
	@echo "✓ Built: $(BINDIR)/$(BINNAME)"
	@ls -lh $(BINDIR)/$(BINNAME)

# Test with sample data
test: build
	@echo "Testing Go demo program..."
	@if [ -f "$(TESTDATA)/all_clients.pcap" ] && [ -f "$(TESTDATA)/all_clients_sslkey.log" ]; then \
		$(BINDIR)/$(BINNAME) \
			-pcap $(TESTDATA)/all_clients.pcap \
			-sslkeylog $(TESTDATA)/all_clients_sslkey.log \
			-har ../../test/result/all_clients.har && \
		echo "" && \
		echo "✓ Test passed!" && \
		echo "  Output: ../../test/result/all_clients.har"; \
	else \
		echo "⚠ Test data not found, skipping test"; \
		echo "  Expected: $(TESTDATA)/all_clients.pcap"; \
		echo "  Expected: $(TESTDATA)/all_clients_sslkey.log"; \
	fi

# Clean built files
clean:
	@echo "Cleaning go_demo..."
	@rm -f $(BINDIR)/$(BINNAME)
	@echo "✓ Cleaned"

# Help
help:
	@echo "Go Demo Makefile Targets:"
	@echo "  all (default) - Build the Go demo program"
	@echo "  build         - Build the program"
	@echo "  test          - Build and test with sample data"
	@echo "  clean         - Remove built binaries"
	@echo "  help          - Show this help message"
	@echo ""
	@echo "This demo uses the Go API directly"
	@echo ""
	@echo "Usage:"
	@echo "  $(BINDIR)/$(BINNAME) -pcap <file> -sslkeylog <file> -har <file>"

