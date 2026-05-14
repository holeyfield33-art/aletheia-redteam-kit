#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${ROOT_DIR}/.venv"

if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
  echo "[verify] ERROR: virtualenv not found. Run ./scripts/bootstrap.sh first."
  exit 1
fi

echo "[verify] Running Python regression checks"
cd "${ROOT_DIR}"
"${VENV_DIR}/bin/python" -m pytest -q tests/test_runner.py tests/test_catalog.py

echo "[verify] Running Sovereign dashboard lint/test/build"
cd "${ROOT_DIR}/dashboard/sovereign-command-center"
npm run lint
npm test
npm run build

echo "[verify] Environment verification passed"
