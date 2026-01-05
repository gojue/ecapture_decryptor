#!/bin/bash
# version.sh - Version management utility
# Usage: ./scripts/version.sh <command> [version]

set -e

CAPI_FILE="capi/main.go"
CHANGELOG_FILE="CHANGELOG.md"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Get current version from capi/main.go
get_current_version() {
    grep -o 'ecapture_decryptor v[0-9.]*' "$CAPI_FILE" | head -1 | sed 's/ecapture_decryptor v//'
}

# Update version in capi/main.go
update_version() {
    local new_version="$1"
    local version_number="${new_version#v}"

    echo -e "${YELLOW}Updating version to ${new_version}...${NC}"

    # Backup
    cp "$CAPI_FILE" "${CAPI_FILE}.bak"

    # Update version
    sed -i.tmp "s/ecapture_decryptor v[0-9.]*/ecapture_decryptor v${version_number}/" "$CAPI_FILE"
    rm -f "${CAPI_FILE}.tmp"

    echo -e "${GREEN}✓ Updated ${CAPI_FILE}${NC}"
}

# Bump version
bump_version() {
    local bump_type="$1"
    local current=$(get_current_version)

    IFS='.' read -r major minor patch <<< "$current"

    case "$bump_type" in
        major)
            major=$((major + 1))
            minor=0
            patch=0
            ;;
        minor)
            minor=$((minor + 1))
            patch=0
            ;;
        patch)
            patch=$((patch + 1))
            ;;
        *)
            echo -e "${RED}Error: Invalid bump type. Use: major, minor, or patch${NC}"
            exit 1
            ;;
    esac

    echo "v${major}.${minor}.${patch}"
}

# Show current version
show_version() {
    local current=$(get_current_version)
    echo -e "${GREEN}Current version: v${current}${NC}"
}

# Create changelog entry
create_changelog_entry() {
    local version="$1"
    local date=$(date '+%Y-%m-%d')

    echo -e "${YELLOW}Creating CHANGELOG entry for ${version}...${NC}"

    # Create temporary file with new entry
    cat > /tmp/changelog_entry.md << EOF

## [${version}] - ${date}

### Added
-

### Changed
-

### Fixed
-

EOF

    # Insert after [Unreleased] section
    if grep -q "\[Unreleased\]" "$CHANGELOG_FILE"; then
        # Find line number of [Unreleased] section
        local line_num=$(grep -n "\[Unreleased\]" "$CHANGELOG_FILE" | head -1 | cut -d: -f1)
        # Skip to the end of [Unreleased] section (find next ## or ---)
        local insert_line=$((line_num + 10))

        # Insert new entry
        {
            head -n "$insert_line" "$CHANGELOG_FILE"
            cat /tmp/changelog_entry.md
            tail -n +$((insert_line + 1)) "$CHANGELOG_FILE"
        } > /tmp/changelog_new.md

        mv /tmp/changelog_new.md "$CHANGELOG_FILE"
        echo -e "${GREEN}✓ Created CHANGELOG entry${NC}"
    else
        echo -e "${RED}Error: Could not find [Unreleased] section in CHANGELOG${NC}"
        exit 1
    fi
}

# Main
case "$1" in
    show|current)
        show_version
        ;;

    set)
        if [ -z "$2" ]; then
            echo -e "${RED}Error: Version required${NC}"
            echo "Usage: $0 set <version>"
            exit 1
        fi
        update_version "$2"
        create_changelog_entry "$2"
        echo -e "${GREEN}✓ Version updated to $2${NC}"
        echo -e "${YELLOW}Next steps:${NC}"
        echo "  1. Update CHANGELOG.md with actual changes"
        echo "  2. Commit changes: git commit -am 'Bump version to $2'"
        echo "  3. Create tag: git tag $2"
        echo "  4. Push: git push origin main --tags"
        ;;

    bump)
        if [ -z "$2" ]; then
            echo -e "${RED}Error: Bump type required${NC}"
            echo "Usage: $0 bump <major|minor|patch>"
            exit 1
        fi
        new_version=$(bump_version "$2")
        update_version "$new_version"
        create_changelog_entry "$new_version"
        echo -e "${GREEN}✓ Version bumped to ${new_version}${NC}"
        echo -e "${YELLOW}Next steps:${NC}"
        echo "  1. Update CHANGELOG.md with actual changes"
        echo "  2. Commit changes: git commit -am 'Bump version to ${new_version}'"
        echo "  3. Create tag: git tag ${new_version}"
        echo "  4. Push: git push origin main --tags"
        ;;

    *)
        echo "Version Management Utility"
        echo ""
        echo "Usage: $0 <command> [args]"
        echo ""
        echo "Commands:"
        echo "  show                 - Show current version"
        echo "  set <version>        - Set specific version (e.g., v2.1.0)"
        echo "  bump <type>          - Bump version (major|minor|patch)"
        echo ""
        echo "Examples:"
        echo "  $0 show"
        echo "  $0 set v2.1.0"
        echo "  $0 bump minor"
        exit 1
        ;;
esac

