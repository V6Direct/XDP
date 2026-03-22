#!/usr/bin/env bash
# scripts/setup.sh – Developer setup: generates go.sum and installs tools.
set -euo pipefail

echo "==> Generating go.sum..."
go mod tidy
echo "✓  go.sum generated"

echo "==> Verifying modules..."
go mod verify
echo "✓  modules verified"

echo ""
echo "✓  Setup complete. Commit go.sum to the repository."
