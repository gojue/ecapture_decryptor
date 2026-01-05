#!/bin/bash
# add_copyright.sh - Add copyright header to all Go source files

COPYRIGHT_HEADER="// Copyright (c) 2024-2026 CFC4N (cfc4n.cs@gmail.com). All Rights Reserved.
//
// This source code is licensed under a proprietary license.
// Unauthorized copying, modification, or distribution is strictly prohibited.
// See LICENSE file for details.
"

# Find all .go files excluding vendor and test directories
find . -name "*.go" \
  -not -path "*/vendor/*" \
  -not -path "*/.git/*" \
  -not -path "*/bin/*" \
  -type f | while read -r file; do

  # Check if file already has copyright
  if ! grep -q "Copyright (c) 2024-2026 CFC4N" "$file"; then
    echo "Adding copyright to: $file"

    # Create temp file with copyright header
    {
      echo "$COPYRIGHT_HEADER"
      cat "$file"
    } > "$file.tmp"

    # Replace original file
    mv "$file.tmp" "$file"
  else
    echo "Skipping (already has copyright): $file"
  fi
done

echo ""
echo "✓ Copyright headers added to all Go source files"

