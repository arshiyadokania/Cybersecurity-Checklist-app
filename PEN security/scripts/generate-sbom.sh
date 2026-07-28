#!/usr/bin/env bash
#
# generate-sbom.sh — produce a CycloneDX SBOM for THIS repo using syft.
# The SBOM is a build artifact (inventory of what shipped), uploaded by CI.

set -euo pipefail

# Pinned (mirror securityConfig.js TOOL_VERSIONS; explicit version pin only).
SYFT_VERSION="1.18.1"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORTS="$ROOT_DIR/reports"
SCAN_TARGET="${SCAN_TARGET:-$ROOT_DIR}"

mkdir -p "$REPORTS"

echo ">> generating CycloneDX SBOM with syft $SYFT_VERSION"
syft scan "dir:$SCAN_TARGET" \
  --output "cyclonedx-json=$REPORTS/sbom.cyclonedx.json"

echo ">> SBOM written to $REPORTS/sbom.cyclonedx.json"