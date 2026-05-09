#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_DIR="${ROOT_DIR}/.venv"
PYTHON_BIN="${PYTHON_BIN:-python3}"

echo "[bootstrap] Root: ${ROOT_DIR}"

if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
  echo "[bootstrap] ERROR: ${PYTHON_BIN} is not available. Install Python 3.11+ first."
  exit 1
fi

echo "[bootstrap] Creating/updating virtual environment at ${VENV_DIR}"
"${PYTHON_BIN}" -m venv "${VENV_DIR}"

echo "[bootstrap] Installing Python dependencies (core + extras)"
"${VENV_DIR}/bin/python" -m pip install --upgrade pip
"${VENV_DIR}/bin/python" -m pip install -e ".[dev,verify,web,deps]"

echo "[bootstrap] Installing Playwright browser runtime (chromium)"
"${VENV_DIR}/bin/python" -m playwright install chromium

echo "[bootstrap] Installing dashboard Node dependencies with lockfile"
cd "${ROOT_DIR}/dashboard/sovereign-command-center"
npm ci

echo "[bootstrap] Ensuring .env exists from template"
cd "${ROOT_DIR}"
if [[ ! -f .env ]]; then
  cp .env.example .env
  echo "[bootstrap] Created .env from .env.example"
else
  echo "[bootstrap] .env already present, not modifying"
fi

echo "[bootstrap] Complete. Run ./scripts/verify.sh to validate environment."
