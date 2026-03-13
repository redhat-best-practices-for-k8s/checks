#!/usr/bin/env bash
# map-uts.sh — Show unit test coverage for each registered check.
# Parses register.go files for check Name/Fn pairs, then searches
# *_test.go files for calls to each Fn.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPFILE=$(mktemp)
trap 'rm -f "$TMPFILE"' EXIT

categories=(accesscontrol lifecycle networking observability performance platform operator manageability)

for cat in "${categories[@]}"; do
    dir="$ROOT/$cat"
    regfile="$dir/register.go"
    [ -f "$regfile" ] || continue

    paste -d'|' \
        <(grep -oE 'Name:[[:space:]]*"[^"]+"' "$regfile" | sed 's/Name:[[:space:]]*"//;s/"//') \
        <(grep -oE 'Fn:[[:space:]]*[A-Za-z0-9_]+' "$regfile" | sed 's/Fn:[[:space:]]*//') |
    while IFS='|' read -r name fn; do
        if grep -rqE "(^|[^A-Za-z0-9_])${fn}([^A-Za-z0-9_]|$)" "$dir"/*_test.go 2>/dev/null; then
            ut="Yes"
        else
            ut="No"
        fi
        printf "%-60s %-30s %s\n" "$name" "$fn" "$ut"
        echo "$ut" >> "$TMPFILE"
    done
done

total=$(wc -l < "$TMPFILE" | tr -d ' ')
covered=$(grep -c "Yes" "$TMPFILE" || true)
uncovered=$((total - covered))

echo ""
echo "Total: $total  Covered: $covered  Uncovered: $uncovered"

if [ "$uncovered" -gt 0 ]; then
    echo ""
    echo "Uncovered checks:"
    # Re-scan to list uncovered names
    for cat in "${categories[@]}"; do
        dir="$ROOT/$cat"
        regfile="$dir/register.go"
        [ -f "$regfile" ] || continue

        paste -d'|' \
            <(grep -oE 'Name:[[:space:]]*"[^"]+"' "$regfile" | sed 's/Name:[[:space:]]*"//;s/"//') \
            <(grep -oE 'Fn:[[:space:]]*[A-Za-z0-9_]+' "$regfile" | sed 's/Fn:[[:space:]]*//') |
        while IFS='|' read -r name fn; do
            if ! grep -rqE "(^|[^A-Za-z0-9_])${fn}([^A-Za-z0-9_]|$)" "$dir"/*_test.go 2>/dev/null; then
                echo "  - $name"
            fi
        done
    done
fi
