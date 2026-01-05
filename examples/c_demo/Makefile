# Makefile for C Demo Programs
# Compiles all C examples that use libecapture_decryptor static library

# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -O2 -I../../include
LDFLAGS := -L../../lib
LIBS := -lecapture_decryptor -lpthread

# Platform-specific settings
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    # macOS requires CoreFoundation and Security frameworks
    LIBS += -framework CoreFoundation -framework Security
endif
ifeq ($(UNAME_S),Linux)
    # Linux may require additional libraries
    LIBS += -lresolv
endif

# Paths
LIBDIR := ../../lib
INCDIR := ../../include
BINDIR := ../../bin
LIBNAME := libecapture_decryptor.a
HEADER := libecapture_decryptor.h
TESTDATA := ../../test/testdata

# Source files and targets
SOURCES := $(wildcard *.c)
BASENAMES := $(basename $(SOURCES))
TARGETS := $(addprefix $(BINDIR)/,$(BASENAMES))

# Default target
.PHONY: all clean test help build-lib

all: check-lib $(TARGETS)

# Build library if it doesn't exist
build-lib:
	@echo "Building static library from c_demo..."
	@cd ../.. && $(MAKE) build-static

# Check if library exists
check-lib:
	@mkdir -p $(BINDIR)
	@if [ ! -f "$(LIBDIR)/$(LIBNAME)" ]; then \
		echo "Static library not found, building it..."; \
		$(MAKE) build-lib; \
	fi
	@if [ ! -f "$(INCDIR)/$(HEADER)" ]; then \
		echo "ERROR: $(INCDIR)/$(HEADER) not found!"; \
		echo "Please build the library first:"; \
		echo "  cd ../.. && make build-static"; \
		exit 1; \
	fi

# Build each executable
$(BINDIR)/%: %.c $(LIBDIR)/$(LIBNAME)
	@echo "Building $@..."
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LIBS)
	@echo "✓ Built: $@"

# Clean built files
clean:
	@echo "Cleaning C demo programs..."
	@rm -f $(TARGETS)
	@echo "✓ Cleaned"

# Test targets
test: test-offline test-stream

test-offline: $(BINDIR)/offline_decryption
	@echo "Testing offline_decryption..."
	@if [ -f "$(TESTDATA)/all_clients.pcap" ] && [ -f "$(TESTDATA)/all_clients_sslkey.log" ]; then \
		$(BINDIR)/offline_decryption $(TESTDATA)/all_clients.pcap $(TESTDATA)/all_clients_sslkey.log output_offline.json && \
		echo "✓ offline_decryption test passed" && \
		echo "  Output: output_offline.json"; \
	else \
		echo "⚠ Test data not found, skipping test"; \
	fi

test-stream: $(BINDIR)/stream_decryption
	@echo "Testing stream_decryption..."
	@if [ -f "$(TESTDATA)/all_clients.pcap" ] && [ -f "$(TESTDATA)/all_clients_sslkey.log" ]; then \
		cat $(TESTDATA)/all_clients.pcap | $(BINDIR)/stream_decryption $(TESTDATA)/all_clients_sslkey.log output_stream.json && \
		echo "✓ stream_decryption test passed" && \
		echo "  Output: output_stream.json"; \
	else \
		echo "⚠ Test data not found, skipping test"; \
	fi

# Help target
help:
	@echo "C Demo Makefile Targets:"
	@echo "  all          - Build all demo programs (default)"
	@echo "  clean        - Remove all built executables"
	@echo "  test         - Run tests for all demos"
	@echo "  test-offline - Test offline_decryption only"
	@echo "  test-stream  - Test stream_decryption only"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Individual targets:"
	@echo "  $(BINDIR)/offline_decryption   - Decrypt offline pcap files"
	@echo "  $(BINDIR)/stream_decryption    - Decrypt pcap from stdin"
	@echo "  $(BINDIR)/live_capture_simple  - Live capture demo (API example)"
	@echo ""
	@echo "Build output:"
	@echo "  All executables are built in: $(BINDIR)/"
	@echo ""
	@echo "Prerequisites:"
	@echo "  Run 'cd ../.. && make build-lib' first to build the library"

