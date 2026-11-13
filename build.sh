#!/usr/bin/env bash
# Build the Privara Caido plugin: exact versions from package-lock.json, unit tests, typecheck, package.
#   ./build.sh          -> dist/plugin_package.zip
# Needs Node >= 23 (the tests run .ts by type stripping) and network access to the npm registry once.
set -euo pipefail
cd "$(dirname "$0")"
npm ci --ignore-scripts --no-audit --no-fund
node --test test/core.test.ts
npx tsc -p tsconfig.json --noEmit
npx caido-dev build
# fixed order, timestamp and level, so the same sources give the same package bytes
node normalise-zip.mjs dist/plugin_package.zip
# the BUILT backend, in Node with a fake Caido SDK, against a loopback stub of the Privara API
node test/backend.smoke.mjs
ls -l dist/plugin_package.zip
