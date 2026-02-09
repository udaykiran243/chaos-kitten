#!/bin/bash
set -e

# Installation logic
echo "::group::Chaos Kitten Setup"
if [ -f "/github/workspace/pyproject.toml" ] && grep -q "chaos-kitten" "/github/workspace/pyproject.toml"; then
    echo "Detected Chaos Kitten repository. Installing from workspace..."
    pip install /github/workspace
else
    echo "Checking for Chaos Kitten installation..."
    if ! command -v chaos-kitten &> /dev/null; then
        echo "Installing Chaos Kitten from git..."
        pip install git+https://github.com/Apertre/chaos-kitten.git@main
    fi
fi
echo "::endgroup::"

# Ensure report directory exists
mkdir -p ./reports

echo "::group::Security Scan"
echo "Running with arguments: $@"
echo "Threshold: ${SEVERITY_THRESHOLD:-high}"

# Run scan, allowing failure so we can still process reports
chaos-kitten scan "$@" --format sarif --output ./reports || echo "Scan command exited with error"

# Set outputs
if [ -f "./reports/results.sarif" ]; then
    echo "sarif-file=$(pwd)/reports/results.sarif" >> $GITHUB_OUTPUT
fi

if [ -f "./reports/results.html" ]; then
    echo "report-file=$(pwd)/reports/results.html" >> $GITHUB_OUTPUT
fi
echo "::endgroup::"

echo "::group::Results Analysis"
# Run validation and summary generation
python3 /app/sarif-converter.py ./reports "${SEVERITY_THRESHOLD:-high}"
EXIT_CODE=$?

if [ -f "scan-summary.md" ] && [ -n "$GITHUB_STEP_SUMMARY" ]; then
    cat scan-summary.md >> "$GITHUB_STEP_SUMMARY"
fi

echo "::endgroup::"
exit $EXIT_CODE
