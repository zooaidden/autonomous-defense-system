#!/usr/bin/env bash
# =============================================================================
# LoongArch / Kylin V11 Python C-extension prebuild script
# =============================================================================
#
# Several Python packages used by agent-brain contain C or Rust extensions
# that must be compiled from source on LoongArch64. This script automates
# the prebuild step so `pip install -e .[mcp]` inside agent-brain/ succeeds
# on the first try.
#
# Packages that need local compilation:
#
#   pydantic-core   (Rust / maturin)   – Pydantic v2 runtime core
#   cryptography    (C + OpenSSL)      – TLS, key derivation
#   httpcore        (C extension opt)  – HTTP transport (optional, pure fallback)
#
# Usage:
#
#   1. Install system prerequisites once:
#
#        sudo dnf install -y gcc gcc-c++ rust cargo \
#          python3.11-devel openssl-devel libffi-devel
#
#   2. Run this script inside the agent-brain venv:
#
#        cd /opt/autonomous-defense-system/agent-brain
#        python3.11 -m venv .venv
#        source .venv/bin/activate
#        bash ../deploy/kylin/prebuild-loongarch.sh
#
#   3. Then install the remaining packages normally:
#
#        pip install -e .[mcp]
#
# Exit codes:
#   0 - all prebuild steps completed
#   1 - system prerequisite missing
#   2 - compilation failed for one or more packages
# =============================================================================

set -euo pipefail

RED='\033[1;31m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

echo "================================================================"
echo " Kylin V11 / LoongArch Python C-extension prebuild"
echo "================================================================"

# ---------------------------------------------------------------------------
# Check system prerequisites
# ---------------------------------------------------------------------------
MISSING=()
for cmd in gcc cargo python3.11; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    MISSING+=("$cmd")
  fi
done

if (( ${#MISSING[@]} > 0 )); then
  echo -e "${RED}Missing prerequisites: ${MISSING[*]}${NC}"
  echo "Install with:"
  echo "  sudo dnf install -y gcc gcc-c++ rust cargo python3.11-devel openssl-devel libffi-devel"
  exit 1
fi

# Verify we're in a Python 3.11+ venv.
PY_VER=$(python3.11 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "0")
if [[ ! "$PY_VER" =~ ^3\.1[1-9]|^3\.[2-9] ]]; then
  echo -e "${YELLOW}Warning: Python version is $PY_VER; agent-brain needs >=3.11${NC}"
fi

# ---------------------------------------------------------------------------
# Upgrade pip and build tools
# ---------------------------------------------------------------------------
echo ""
echo "--- Upgrading pip, setuptools, wheel ---"
pip install --upgrade pip setuptools wheel

# ---------------------------------------------------------------------------
# Prebuild pydantic-core (Rust / maturin)
# ---------------------------------------------------------------------------
echo ""
echo "--- Building pydantic-core (Rust extension) ---"
# Ensure maturin is available (pydantic-core build system).
pip install --upgrade maturin
if pip install --no-binary pydantic-core "pydantic-core>=2.14"; then
  echo -e "${GREEN}pydantic-core built successfully${NC}"
else
  echo -e "${RED}pydantic-core build FAILED${NC}"
  echo "Check:  cargo --version, rustup show"
  echo "If cargo is missing:  curl https://sh.rustup.rs -sSf | sh -s -- -y && source ~/.cargo/env"
  exit 2
fi

# ---------------------------------------------------------------------------
# Prebuild cryptography (C + OpenSSL)
# ---------------------------------------------------------------------------
echo ""
echo "--- Building cryptography (C extension) ---"
if pip install --no-binary cryptography "cryptography>=41"; then
  echo -e "${GREEN}cryptography built successfully${NC}"
else
  echo -e "${YELLOW}cryptography build FAILED — installing binary wheel${NC}"
  echo "This may mean openssl-devel or libffi-devel is missing."
  echo "Install:  sudo dnf install -y openssl-devel libffi-devel"
  # Fall back to binary if available (unlikely on LoongArch).
  pip install "cryptography>=41" || {
    echo -e "${RED}cryptography installation FAILED completely${NC}"
    exit 2
  }
fi

# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------
echo ""
echo "--- Verification ---"
python3.11 -c '
import pydantic_core; print(f"  pydantic-core {pydantic_core.__version__}  OK")
import cryptography;  print(f"  cryptography {cryptography.__version__}   OK")
print("")
print("All prebuilt extensions verified.")
' && echo -e "${GREEN}PASS${NC}" || {
  echo -e "${RED}Verification FAILED — one or more imports raised an error${NC}"
  exit 2
}

echo ""
echo -e "${GREEN}prebuild-loongarch.sh complete.${NC}"
echo "You can now run:  pip install -e .[mcp]"
exit 0
