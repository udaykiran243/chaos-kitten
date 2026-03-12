#!/bin/bash
set -e
echo "Building hardened Docker image..."
docker build -t chaos-kitten:test .

echo "Running Privilege Test (whoami)..."
USER_OUT=$(docker run --rm chaos-kitten:test whoami)
if [ "$USER_OUT" != "chaos" ]; then
    echo "FAIL: Expected user 'chaos', got '$USER_OUT'"
    exit 1
else
    echo "PASS: Container runs as user 'chaos'"
fi

echo "Testing execution (checking version/help command)..."
docker run --rm chaos-kitten:test --help > /dev/null
echo "PASS: Container executes successfully"

echo "Docker hardening verification complete."
