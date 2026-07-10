#!/usr/bin/env bash
set -euo pipefail
mkdir -p lab-output

docker run --rm \
  -v "$(pwd):/workspace" \
  -w /workspace \
  anchore/syft:v1.28.0 dir:. -o cyclonedx-json=lab-output/sbom.cdx.json

echo "SBOM written to lab-output/sbom.cdx.json"
