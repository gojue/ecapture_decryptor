#!/bin/bash
# build-multiplatform.sh - Build releases for multiple platforms using Docker
# Usage: ./scripts/build-multiplatform.sh <version>

set -e

if [ -z "$1" ]; then
    echo "Error: Version required"
    echo "Usage: $0 <version>"
    echo "Example: $0 v2.0.0"
    exit 1
fi

source "$(dirname "$0")/version.sh"
VERSION_NUMBER="${1#v}"
validate_version "$VERSION_NUMBER"
get_current_version > /dev/null
VERSION="v${VERSION_NUMBER}"

echo "Building multi-platform releases for version: $VERSION"
echo ""

# Build for current platform (native)
echo "=== Building for native platform ==="
./scripts/release.sh "$VERSION"
echo ""

# Build for Linux AMD64 using Docker
echo "=== Building for Linux AMD64 (Docker) ==="
if command -v docker &> /dev/null; then
    docker run --rm --platform linux/amd64 -v "$PWD:/workspace" -w /workspace golang:1.26 bash -ec '
        apt-get update
        apt-get install -y build-essential
        ./scripts/release.sh "$1"
    ' bash "$VERSION"
else
    echo "Docker not available, skipping Linux AMD64 build"
fi
echo ""

# Build for Linux ARM64 using Docker
echo "=== Building for Linux ARM64 (Docker) ==="
if command -v docker &> /dev/null; then
    docker run --rm --platform linux/arm64 -v "$PWD:/workspace" -w /workspace golang:1.26 bash -ec '
        apt-get update
        apt-get install -y build-essential
        ./scripts/release.sh "$1"
    ' bash "$VERSION"
else
    echo "Docker not available, skipping Linux ARM64 build"
fi
echo ""

echo "Multi-platform build complete!"
echo "Check ./dist/ directory for all builds"
ls -lh ./dist/*.tar.gz

