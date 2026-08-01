#!/usr/bin/env bash
set -euo pipefail
project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_root"
cargo fetch
cargo test --workspace
cd apps/web
npm ci --ignore-scripts --no-audit --no-fund --cache "$project_root/.npm-cache"
npm run build
echo "Robox is ready. Run ./scripts/dev.sh and open http://127.0.0.1:3000"

