#!/usr/bin/env bash
set -u
echo "HOME=$HOME"
echo "USER=$(whoami)"
echo "--- os ---"
. /etc/os-release && echo "$PRETTY_NAME"
echo "--- tools ---"
for t in git curl jq node npm go docker; do
  if command -v "$t" >/dev/null 2>&1; then
    printf '%-8s %s\n' "$t" "$($t --version 2>&1 | head -1)"
  else
    printf '%-8s MISSING\n' "$t"
  fi
done
echo "--- docker ---"
docker ps --format '{{.Names}}' 2>&1 | head -3
echo "OK"
