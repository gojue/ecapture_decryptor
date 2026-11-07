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
    local marker version
    marker=$(grep -o 'C\.CString("eCapture Decryptor v[^[:space:]"]* -' "$CAPI_FILE") || {
        echo "Error: Version marker missing from ${CAPI_FILE}" >&2
        return 1
    }
    if [[ "$marker" == *$'\n'* ]]; then
        echo "Error: Multiple version markers in ${CAPI_FILE}" >&2
        return 1
    fi
    version=${marker#*eCapture Decryptor v}
    version=${version% -}
    validate_version "$version" || return 1
    printf '%s\n' "$version"
}

# Accept a bare SemVer, not shell commands, paths, or sed replacement syntax.
validate_version() {
    local version="${1:-}" identifier prerelease
    local pattern='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$'
    if [[ ! "$version" =~ $pattern ]]; then
        echo "Error: Invalid version; expected MAJOR.MINOR.PATCH with optional prerelease/build metadata" >&2
        return 1
    fi
    prerelease=${version%%+*}
    if [[ "$prerelease" == *-* ]]; then
        prerelease=${prerelease#*-}
        local IFS='.'
        for identifier in $prerelease; do
            if [[ "$identifier" =~ ^0[0-9]+$ ]]; then
                echo "Error: Numeric prerelease identifiers must not have leading zeroes" >&2
                return 1
            fi
        done
    fi
}

# Update version in capi/main.go
update_version() {
    local new_version="${1:-}"
    local version_number="${new_version#v}"
    local current temporary
    validate_version "$version_number" || return 1
    current=$(get_current_version) || return 1

    echo -e "${YELLOW}Updating version to v${version_number}...${NC}"
    if [ "$current" != "$version_number" ]; then
        temporary=$(mktemp "${CAPI_FILE}.XXXXXX") || return 1
        if ! cp -p "$CAPI_FILE" "$temporary" ||
            ! sed "s/\(C\.CString(\"eCapture Decryptor v\)[^[:space:]\"]*\( -\)/\1${version_number}\2/" "$CAPI_FILE" > "$temporary" ||
            ! cp -p "$CAPI_FILE" "${CAPI_FILE}.bak" ||
            ! mv "$temporary" "$CAPI_FILE"; then
            rm -f "$temporary"
            return 1
        fi
    fi

    echo -e "${GREEN}✓ Updated ${CAPI_FILE}${NC}"
}

# Bump version
bump_version() {
    local bump_type="$1" current major minor patch
    current=$(get_current_version) || return 1
    if [[ "$current" == *-* || "$current" == *+* ]]; then
        echo "Error: Cannot bump a prerelease/build-metadata version; use set explicitly" >&2
        return 1
    fi

    IFS='.' read -r major minor patch <<< "$current"
    if [ "${#major}" -gt 18 ] || [ "${#minor}" -gt 18 ] || [ "${#patch}" -gt 18 ]; then
        echo "Error: Version component is too large to bump safely" >&2
        return 1
    fi

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
            echo -e "${RED}Error: Invalid bump type. Use: major, minor, or patch${NC}" >&2
            return 1
            ;;
    esac

    echo "v${major}.${minor}.${patch}"
}

# Show current version
show_version() {
    local current
    current=$(get_current_version) || return 1
    echo -e "${GREEN}Current version: v${current}${NC}"
}

# Create changelog entry
create_changelog_entry() {
    local version="v${1#v}" entry_date temporary
    validate_version "${version#v}" || return 1
    if [ ! -f "$CHANGELOG_FILE" ] || [ ! -r "$CHANGELOG_FILE" ]; then
        echo "Error: Cannot read ${CHANGELOG_FILE}" >&2
        return 1
    fi
    # Re-setting an existing release must not duplicate its history entry.
    if awk -v version="$version" '$1 ~ /^#+$/ && ($2 == version || $2 == "[" version "]") { found=1 } END { exit !found }' "$CHANGELOG_FILE"; then
        return 0
    fi
    entry_date=$(date '+%Y-%m-%d') || return 1
    temporary=$(mktemp "${CHANGELOG_FILE}.XXXXXX") || return 1

    echo -e "${YELLOW}Creating CHANGELOG entry for ${version}...${NC}"

    # The repository keeps '# v...' release headings without an Unreleased
    # section. Prepend a matching entry and preserve all existing content.
    if ! cp -p "$CHANGELOG_FILE" "$temporary" || ! {
        printf '# %s (%s)\n\n## Added\n-\n\n## Changed\n-\n\n## Fixed\n-\n\n<hr>\n\n' "$version" "$entry_date" &&
        cat "$CHANGELOG_FILE"
    } > "$temporary" || ! mv "$temporary" "$CHANGELOG_FILE"; then
        rm -f "$temporary"
        return 1
    fi
    echo -e "${GREEN}✓ Created CHANGELOG entry${NC}"
}

# Other build scripts reuse these functions without running this CLI.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
    return 0
fi

# Main
case "${1:-}" in
    show|current)
        show_version
        ;;

    set)
        if [ -z "${2:-}" ]; then
            echo -e "${RED}Error: Version required${NC}"
            echo "Usage: $0 set <version>"
            exit 1
        fi
        if [ ! -f "$CHANGELOG_FILE" ] || [ ! -r "$CHANGELOG_FILE" ]; then
            echo "Error: Cannot read ${CHANGELOG_FILE}" >&2
            exit 1
        fi
        new_version="v${2#v}"
        update_version "$new_version"
        create_changelog_entry "$new_version"
        echo -e "${GREEN}✓ Version updated to $new_version${NC}"
        echo -e "${YELLOW}Next steps:${NC}"
        echo "  1. Update CHANGELOG.md with actual changes"
        echo "  2. Commit changes: git commit -am 'Bump version to $new_version'"
        echo "  3. Create tag: git tag $new_version"
        echo "  4. Push: git push origin master --tags"
        ;;

    bump)
        if [ -z "${2:-}" ]; then
            echo -e "${RED}Error: Bump type required${NC}"
            echo "Usage: $0 bump <major|minor|patch>"
            exit 1
        fi
        if [ ! -f "$CHANGELOG_FILE" ] || [ ! -r "$CHANGELOG_FILE" ]; then
            echo "Error: Cannot read ${CHANGELOG_FILE}" >&2
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
        echo "  4. Push: git push origin master --tags"
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

