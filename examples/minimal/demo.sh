#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG="$ROOT_DIR/examples/minimal/soipack.config.yaml"
CLI_DIST="$ROOT_DIR/packages/cli/dist/index.js"

if [ ! -f "$CLI_DIST" ]; then
  echo "Building SOIPack CLI..."
  npm run --workspace @soipack/cli build >/dev/null
fi

echo "Running pipeline with $CONFIG"
node "$CLI_DIST" run --config "$CONFIG"
