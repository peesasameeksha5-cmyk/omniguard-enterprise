#!/usr/bin/env bash
# ==============================================================================
# OmniGuard Enterprise — One-command publish everything
# Usage: ./publish-all.sh
# Requires: .env.credentials with your keys filled in
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ─── Load credentials ─────────────────────────────────────────────────────────
ENV_FILE=".env.credentials"
if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: $ENV_FILE not found. Copy it and fill in your credentials first."
  exit 1
fi

# Export all non-comment, non-empty lines
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

echo "============================================================"
echo "  OmniGuard Enterprise — Publishing All Artifacts"
echo "============================================================"
echo ""

FAILED=()

# ─── 1. Install all deps ──────────────────────────────────────────────────────
echo "▶ Installing dependencies..."
(cd cli && npm ci --ignore-scripts) && echo "  ✓ CLI deps"
(cd vscode-extension && npm ci --ignore-scripts) && echo "  ✓ Extension deps"

# ─── 2. Compile VS Code Extension ────────────────────────────────────────────
echo ""
echo "▶ Compiling VS Code Extension..."
(cd vscode-extension && node_modules/.bin/tsc -p ./ 2>&1) \
  && echo "  ✓ Extension compiled" \
  || { echo "  ✗ Extension compile failed"; FAILED+=("extension-compile"); }

# ─── 3. Package VS Code Extension (.vsix) ────────────────────────────────────
echo ""
echo "▶ Packaging VS Code Extension (.vsix)..."
if command -v vsce &> /dev/null || [ -f vscode-extension/node_modules/.bin/vsce ]; then
  VSCE_CMD="${VSCE_CMD:-vsce}"
  [ -f vscode-extension/node_modules/.bin/vsce ] && VSCE_CMD="vscode-extension/node_modules/.bin/vsce"
  (cd vscode-extension && "$VSCE_CMD" package --no-yarn -o omniguard-enterprise.vsix 2>&1) \
    && echo "  ✓ VSIX packaged: vscode-extension/omniguard-enterprise.vsix" \
    || { echo "  ✗ VSIX packaging failed (install: npm install -g @vscode/vsce)"; FAILED+=("vsix-package"); }
else
  echo "  ⚠ vsce not found — run: npm install -g @vscode/vsce then re-run this script"
  FAILED+=("vsix-missing-vsce")
fi

# ─── 4. Publish VS Code Extension ────────────────────────────────────────────
if [ -n "${VSCE_PAT:-}" ] && [ -f vscode-extension/omniguard-enterprise.vsix ]; then
  echo ""
  echo "▶ Publishing VS Code Extension to Marketplace..."
  VSCE_CMD="vscode-extension/node_modules/.bin/vsce"
  (cd vscode-extension && "$VSCE_CMD" publish --no-yarn --pat "${VSCE_PAT}" 2>&1) \
    && echo "  ✓ Extension published to VS Code Marketplace" \
    || { echo "  ✗ Extension publish failed (check VSCE_PAT and publisher name)"; FAILED+=("vsix-publish"); }
else
  echo "  ⚠ Skipping VS Code publish — VSCE_PAT not set or .vsix not built"
fi

# ─── 5. Publish CLI to npm ────────────────────────────────────────────────────
if [ -n "${NPM_TOKEN:-}" ]; then
  echo ""
  echo "▶ Publishing CLI to npm..."
  echo "//registry.npmjs.org/:_authToken=${NPM_TOKEN}" > ~/.npmrc
  (cd cli && npm publish --access public 2>&1) \
    && echo "  ✓ CLI published to npm (@omniguard/cli)" \
    || { echo "  ✗ CLI npm publish failed"; FAILED+=("npm-cli"); }
  rm -f ~/.npmrc
else
  echo "  ⚠ Skipping npm publish — NPM_TOKEN not set"
fi

# ─── 6. Build Docker image ────────────────────────────────────────────────────
if command -v docker &> /dev/null; then
  echo ""
  echo "▶ Building Docker image..."
  IMAGE="${DOCKER_IMAGE:-omniguard/omniguard-enterprise}"
  VERSION=$(node -e "console.log(require('./cli/package.json').version)" 2>/dev/null || echo "latest")
  
  docker build \
    -f Dockerfile.production \
    --build-arg VITE_SUPABASE_URL="${SUPABASE_URL:-}" \
    --build-arg VITE_SUPABASE_ANON_KEY="${SUPABASE_ANON_KEY:-}" \
    -t "${IMAGE}:${VERSION}" \
    -t "${IMAGE}:latest" \
    . 2>&1 | tail -20 \
    && echo "  ✓ Docker image built: ${IMAGE}:${VERSION}" \
    || { echo "  ✗ Docker build failed"; FAILED+=("docker-build"); }

  # Push to registry if credentials set
  if [ -n "${DOCKER_PASSWORD:-}" ]; then
    echo "  → Pushing to Docker Hub..."
    echo "${DOCKER_PASSWORD}" | docker login -u "${DOCKER_USERNAME:-omniguard}" --password-stdin 2>&1
    docker push "${IMAGE}:${VERSION}" && docker push "${IMAGE}:latest" \
      && echo "  ✓ Docker image pushed" \
      || { echo "  ✗ Docker push failed"; FAILED+=("docker-push"); }
  else
    echo "  ⚠ DOCKER_PASSWORD not set — skipping push"
  fi
else
  echo "  ⚠ Docker not installed — skipping Docker build"
fi

# ─── 7. Summary ───────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
if [ ${#FAILED[@]} -eq 0 ]; then
  echo "  ✅ All publish steps completed successfully"
else
  echo "  ⚠ Completed with failures:"
  for f in "${FAILED[@]}"; do
    echo "    - $f"
  done
fi
echo "============================================================"
