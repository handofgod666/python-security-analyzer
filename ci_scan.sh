#!/bin/bash

# CI/CD Integration Script for Python Security Analyzer
# Usage: ./ci_scan.sh [path] [--fail-on-warning]

set -e

SCAN_PATH="${1:-.}"
FAIL_ON_WARNING="${2:-}"

echo "=========================================="
echo "Python Security Analyzer - CI/CD Scan"
echo "=========================================="
echo "Scanning: $SCAN_PATH"
echo ""

# Run the scan
if python -m sqli_detector scan "$SCAN_PATH" > scan_results.txt 2>&1; then
    echo "✓ No vulnerabilities found!"
    cat scan_results.txt
    exit 0
else
    echo "✗ Vulnerabilities detected!"
    cat scan_results.txt

    if [ "$FAIL_ON_WARNING" == "--fail-on-warning" ]; then
        echo ""
        echo "Failing build due to security vulnerabilities."
        exit 1
    else
        echo ""
        echo "Build continues despite vulnerabilities (warning mode)."
        exit 0
    fi
fi
