#!/bin/bash
# release.sh - Build and package library releases for different versions
# Usage: ./scripts/release.sh <version>
# Example: ./scripts/release.sh v2.0.0

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="ecapture_decryptor"
AUTHOR="CFC4N"
RELEASE_DIR="./dist"

# Check if version is provided
if [ -z "$1" ]; then
    echo -e "${RED}Error: Version number required${NC}"
    echo "Usage: $0 <version>"
    echo "Example: $0 v2.0.0"
    exit 1
fi

VERSION="$1"
VERSION_NUMBER="${VERSION#v}"  # Remove 'v' prefix if exists

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Building Release: ${VERSION}${NC}"
echo -e "${GREEN}========================================${NC}"

# Check if we're cross-compiling (GOOS/GOARCH env vars are set)
if [ -n "$GOOS" ] && [ -n "$GOARCH" ]; then
    echo -e "${YELLOW}Cross-compilation mode detected${NC}"
    echo -e "${YELLOW}Target: GOOS=$GOOS, GOARCH=$GOARCH${NC}"

    # Use environment variables for cross-compilation
    OS_NAME="$GOOS"
    case "$GOARCH" in
        amd64)
            ARCH_NAME="amd64"
            ;;
        arm64)
            ARCH_NAME="arm64"
            ;;
        *)
            echo -e "${RED}Unsupported GOARCH: $GOARCH${NC}"
            exit 1
            ;;
    esac
else
    # Native build - detect from current system
    echo -e "${YELLOW}Native build mode${NC}"
    OS=$(uname -s)
    ARCH=$(uname -m)

    case "$OS" in
        Darwin)
            OS_NAME="darwin"
            ;;
        Linux)
            OS_NAME="linux"
            ;;
        *)
            echo -e "${RED}Unsupported OS: $OS${NC}"
            exit 1
            ;;
    esac

    case "$ARCH" in
        x86_64)
            ARCH_NAME="amd64"
            ;;
        arm64|aarch64)
            ARCH_NAME="arm64"
            ;;
        *)
            echo -e "${RED}Unsupported architecture: $ARCH${NC}"
            exit 1
            ;;
    esac
fi

# Set shared library extension based on OS
case "$OS_NAME" in
    darwin)
        SHARED_EXT="dylib"
        ;;
    linux)
        SHARED_EXT="so"
        ;;
esac

PLATFORM="${OS_NAME}-${ARCH_NAME}"
RELEASE_NAME="${PROJECT_NAME}-${VERSION}-${PLATFORM}"
RELEASE_PATH="${RELEASE_DIR}/${RELEASE_NAME}"

echo -e "${YELLOW}Target Platform: ${PLATFORM}${NC}"
echo -e "${YELLOW}Release Name: ${RELEASE_NAME}${NC}"
echo ""

# Clean previous build
echo -e "${GREEN}Step 1: Cleaning previous builds...${NC}"
make clean
rm -rf "${RELEASE_PATH}"
mkdir -p "${RELEASE_PATH}"

# Update version in capi/main.go
echo -e "${GREEN}Step 2: Updating version number...${NC}"
sed -i.bak "s/eCapture Decryptor v[0-9.]* -/eCapture Decryptor ${VERSION} -/" capi/main.go
rm -f capi/main.go.bak

# Build static library
echo -e "${GREEN}Step 3: Building static library...${NC}"
make build-static

# Build shared library
echo -e "${GREEN}Step 4: Building shared library...${NC}"
make build-shared

# Copy libraries to release directory
echo -e "${GREEN}Step 5: Packaging libraries...${NC}"
mkdir -p "${RELEASE_PATH}/lib"
mkdir -p "${RELEASE_PATH}/include"
#mkdir -p "${RELEASE_PATH}/docs"

cp lib/libecapture_decryptor.a "${RELEASE_PATH}/lib/"
cp lib/libecapture_decryptor.${SHARED_EXT} "${RELEASE_PATH}/lib/"
cp include/libecapture_decryptor.h "${RELEASE_PATH}/include/"

# Copy license files
echo -e "${GREEN}Step 6: Adding license files...${NC}"
cp LICENSE "${RELEASE_PATH}/"
cp LICENSE-BINARY "${RELEASE_PATH}/"
cp COPYRIGHT "${RELEASE_PATH}/"

# Create README for the release
cat > "${RELEASE_PATH}/README.md" << EOF
# eCapture Decryptor ${VERSION}

Binary library distribution for ${PLATFORM}

## Contents

- \`lib/libecapture_decryptor.a\` - Static library
- \`lib/libecapture_decryptor.${SHARED_EXT}\` - Shared/dynamic library
- \`include/libecapture_decryptor.h\` - C header file
- \`docs/\` - Documentation and examples

## Quick Start

### Using Static Library

\`\`\`bash
gcc -o myapp myapp.c -I./include -L./lib -lecapture_decryptor -lpthread \\
    -framework CoreFoundation -framework Security  # macOS only
\`\`\`

### Using Shared Library

\`\`\`bash
# Compile
gcc -o myapp myapp.c -I./include -L./lib -lecapture_decryptor

# Run (set library path)
export LD_LIBRARY_PATH=./lib:\$LD_LIBRARY_PATH  # Linux
export DYLD_LIBRARY_PATH=./lib:\$DYLD_LIBRARY_PATH  # macOS
./myapp
\`\`\`

## Platform Information

- **Version**: ${VERSION}
- **OS**: ${OS_NAME}
- **Architecture**: ${ARCH_NAME}
- **Build Date**: $(date '+%Y-%m-%d %H:%M:%S')

## License

Copyright (c) 2024-2026 ${AUTHOR}. All Rights Reserved.

**Non-Commercial License** - See LICENSE-BINARY for details.

For commercial use, contact: cfc4n.cs@gmail.com

## Documentation

- Full documentation: https://github.com/cfc4n/${PROJECT_NAME}
- API reference: See \`include/libecapture_decryptor.h\`
- Examples: https://github.com/cfc4n/${PROJECT_NAME}/tree/master/examples

## Support

- Issues: https://github.com/cfc4n/${PROJECT_NAME}/issues
- Email: cfc4n.cs@gmail.com
EOF
#
## Copy examples
echo -e "${GREEN}Step 7: Adding example code...${NC}"
#mkdir -p "${RELEASE_PATH}/docs/examples"
#cp -r examples/c_demo/*.c "${RELEASE_PATH}/docs/examples/" 2>/dev/null || true
#cp -r examples/c_demo/README.md "${RELEASE_PATH}/docs/examples/" 2>/dev/null || true

# Create checksum file
echo -e "${GREEN}Step 8: Generating checksums...${NC}"
cd "${RELEASE_PATH}"
find . -type f ! -name "SHA256SUMS" -exec sha256sum {} \; > SHA256SUMS
cd - > /dev/null

# Create tarball
echo -e "${GREEN}Step 9: Creating archive...${NC}"
cd "${RELEASE_DIR}"
tar -czf "${RELEASE_NAME}.tar.gz" "${RELEASE_NAME}"
cd - > /dev/null

# Create checksum for tarball
echo -e "${GREEN}Step 10: Generating tarball checksum...${NC}"
cd "${RELEASE_DIR}"
sha256sum "${RELEASE_NAME}.tar.gz" > "${RELEASE_NAME}.tar.gz.sha256"
cd - > /dev/null

# Display results
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Release built successfully!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${YELLOW}Release directory:${NC} ${RELEASE_PATH}"
echo -e "${YELLOW}Archive:${NC} ${RELEASE_DIR}/${RELEASE_NAME}.tar.gz"
echo ""
echo -e "${YELLOW}Contents:${NC}"
ls -lh "${RELEASE_PATH}/lib/"
echo ""
echo -e "${YELLOW}Archive size:${NC}"
ls -lh "${RELEASE_DIR}/${RELEASE_NAME}.tar.gz"
echo ""
echo -e "${YELLOW}SHA256:${NC}"
cat "${RELEASE_DIR}/${RELEASE_NAME}.tar.gz.sha256"
echo ""
echo -e "${GREEN}Next steps:${NC}"
echo "1. Test the release:"
echo "   cd ${RELEASE_PATH}"
echo "   gcc -o test docs/examples/offline_decryption.c -I./include -L./lib -lecapture_decryptor"
echo ""
echo "2. Create GitHub release:"
echo "   gh release create ${VERSION} ${RELEASE_DIR}/${RELEASE_NAME}.tar.gz"
echo ""
echo "3. Update release notes and announce"
echo ""

