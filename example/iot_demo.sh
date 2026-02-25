#!/usr/bin/env bash
# ============================================================
# examples/iot_demo.sh (sanitized)
#
# End-to-end reproducible demo for the PU-CP-ABE PoC (pv1).
#
# What it does:
#   1) Build Docker image (Charm/PBC compiled inside)
#   2) Run a container with keys/ mounted to /var/task/keys
#   3) Inside container: clean state -> setup -> userkg -> encrypt -> tkeyup -> decrypt
#   4) Optionally run pytest
#
# Usage (Git Bash / WSL / Linux/macOS):
#   bash examples/iot_demo.sh
#
# Optional env vars:
#   IMAGE_TAG=abe-lambda:pv1
#   PROJECT_DIR=/path/to/project          (default: current directory)
#   HOST_KEYS_DIR=/path/to/keys           (default: $PROJECT_DIR/keys)
#   NO_CACHE=1                            (build with --no-cache)
#   RUN_TESTS=1                           (run pytest after demo)
#   POLICY="A"                            (default: A)
#   T=1                                   (default: 1)
#   USER_ATTRS="A,C"                      (default: A,C)
#   PLAINTEXT="hello world"               (default: hello world)
#   VERBOSE=1                             (print host paths/mounts)
#
# Security/Privacy:
#   - This script avoids printing host absolute paths by default.
#   - Do NOT commit keys/ outputs (pv_setup.json, user keys, tuk, store/) to GitHub.
# ============================================================

set -euo pipefail

IMAGE_TAG="${IMAGE_TAG:-abe-lambda:pv1}"
PROJECT_DIR="${PROJECT_DIR:-$(pwd)}"
HOST_KEYS_DIR="${HOST_KEYS_DIR:-$PROJECT_DIR/keys}"

NO_CACHE="${NO_CACHE:-0}"
RUN_TESTS="${RUN_TESTS:-0}"
VERBOSE="${VERBOSE:-0}"

POLICY="${POLICY:-A}"
T="${T:-1}"
USER_ATTRS="${USER_ATTRS:-A,C}"
PLAINTEXT="${PLAINTEXT:-hello world}"

say() { printf "\n\033[1m%s\033[0m\n" "$*"; }
die() { printf "\nERROR: %s\n" "$*" >&2; exit 1; }

# Convert a host path to a Docker-friendly path.
# - On Git Bash, Docker commonly accepts POSIX paths (via cygpath -u) and/or
#   Windows-style paths. We default to POSIX for safety.
to_docker_path() {
  local p="$1"
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -u "$p"
    return
  fi
  printf "%s" "$p"
}

uuid_from_text() {
  grep -Eo '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' | head -n 1
}

# Preflight
command -v docker >/dev/null 2>&1 || die "docker not found"
command -v grep  >/dev/null 2>&1 || die "grep not found"

mkdir -p "$HOST_KEYS_DIR"
DOCKER_KEYS_DIR="$(to_docker_path "$HOST_KEYS_DIR")"

echo "============================================================"
echo " PU-CP-ABE pv1 Demo (Docker + mounted keys + end-to-end run)"
echo "============================================================"
echo "[host] IMAGE_TAG   = $IMAGE_TAG"
echo "[host] POLICY      = $POLICY"
echo "[host] T           = $T"
echo "[host] USER_ATTRS  = $USER_ATTRS"
if [ "$VERBOSE" = "1" ]; then
  echo "[host] PROJECT_DIR = $PROJECT_DIR"
  echo "[host] HOST_KEYS_DIR = $HOST_KEYS_DIR"
  echo "[host] Mount src (Docker) = $DOCKER_KEYS_DIR"
fi
echo

[ -d "$HOST_KEYS_DIR" ] || die "HOST_KEYS_DIR does not exist: $HOST_KEYS_DIR"

say "[host] Step 0: Build Docker image..."
cd "$PROJECT_DIR"
if [ "$NO_CACHE" = "1" ]; then
  docker build --no-cache -t "$IMAGE_TAG" .
else
  docker build -t "$IMAGE_TAG" .
fi

say "[host] Step 1: Run container and execute end-to-end flow..."
if [ "$VERBOSE" = "1" ]; then
  echo "       (mount: $DOCKER_KEYS_DIR -> /var/task/keys)"
fi

docker run --rm -it   -v "$DOCKER_KEYS_DIR:/var/task/keys"   --entrypoint /bin/bash   "$IMAGE_TAG" -lc "
set -euo pipefail

echo '[container] 1) Check mount: /var/task/keys'
ls -la /var/task/keys

echo
echo '[container] 2) Clean old state (deletes /var/task/keys/*)'
rm -rf /var/task/keys/*
mkdir -p /var/task/keys/store

echo '[container] After cleanup:'
ls -la /var/task/keys

echo
echo '[container] 3) Fresh Setup'
python ta_local.py setup
test -f /var/task/keys/pv_setup.json
echo '[container] OK: pv_setup.json generated.'

echo
echo '[container] 4) Fresh UserKG (do NOT reuse old user key)'
python ta_local.py userkg   --setup /var/task/keys/pv_setup.json   --id user1   --attrs "$USER_ATTRS"   --out /var/task/keys/user1.json
test -f /var/task/keys/user1.json
echo '[container] OK: user1.json generated.'

echo
echo '[container] 5) Encrypt (must be freshly encrypted)'
ENC_OUT=\$(python lambda_encrypt.py   --setup /var/task/keys/pv_setup.json   --policy "$POLICY"   --t "$T"   --plaintext "$PLAINTEXT"   --store_dir /var/task/keys/store)
echo "\$ENC_OUT"

OBJECT_ID=\$(echo "\$ENC_OUT" | grep -Eo "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}" | head -n 1 || true)
if [ -z "\$OBJECT_ID" ]; then
  echo '[container] ERROR: Could not find OBJECT_ID (UUID) in lambda_encrypt output.'
  echo '           Ensure lambda_encrypt.py prints the object_id (UUID).'
  exit 2
fi
echo "[container] OBJECT_ID = \$OBJECT_ID"
echo "\$OBJECT_ID" > /var/task/keys/last_object_id.txt

echo
echo '[container] 6) Generate TUK for time t'
python ta_local.py tkeyup   --setup /var/task/keys/pv_setup.json   --t "$T"   --out /var/task/keys/tuk_t${T}.json
test -f /var/task/keys/tuk_t${T}.json
echo "[container] OK: tuk_t${T}.json generated."

echo
echo '[container] 7) Client decrypt (should Verify OK + plaintext)'
python client_decrypt.py   --setup /var/task/keys/pv_setup.json   --user /var/task/keys/user1.json   --tuk /var/task/keys/tuk_t${T}.json   --object_id "\$OBJECT_ID"   --store_dir /var/task/keys/store

echo
echo '[container] Done.'
"

if [ "$RUN_TESTS" = "1" ]; then
  say "[host] Step 2: Run pytest inside container (optional)..."
  docker run --rm -it     -v "$DOCKER_KEYS_DIR:/var/task/keys"     --entrypoint /bin/bash     "$IMAGE_TAG" -lc "python -m pytest -q tests"
fi

echo
echo "============================================================"
echo " Demo completed."
echo " Outputs are under keys/ (pv_setup.json, user1.json, tuk_*.json, store/, last_object_id.txt)."
echo " ⚠️ Do NOT commit keys/ to GitHub. Add keys/* to .gitignore."
echo "============================================================"
