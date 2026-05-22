#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/../.env}"

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

DOCKERFILE_PATH="${DOCKERFILE_PATH:-$SCRIPT_DIR/../Dockerfile}"
BUILD_CONTEXT="${BUILD_CONTEXT:-$SCRIPT_DIR/..}"
IMAGE_REPOSITORY="${IMAGE_REPOSITORY:-awesomecosmonaut/security-audit-service}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
IMAGE="${IMAGE_REPOSITORY}:${IMAGE_TAG}"

log() {
  echo "[security-audit-service] $*"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[security-audit-service] ERROR: command not found: $1" >&2
    exit 1
  }
}

log "Building and pushing security-audit-service image"
log "Env file: $ENV_FILE"
log "Image: $IMAGE"
log "Dockerfile: $DOCKERFILE_PATH"
log "Build context: $BUILD_CONTEXT"

log "Checking required commands..."
need_cmd docker
log "Commands OK"

[[ -f "$DOCKERFILE_PATH" ]] || {
  echo "[security-audit-service] ERROR: Dockerfile not found: $DOCKERFILE_PATH" >&2
  exit 1
}

[[ -d "$BUILD_CONTEXT" ]] || {
  echo "[security-audit-service] ERROR: build context not found: $BUILD_CONTEXT" >&2
  exit 1
}

log "Docker build..."
docker build -f "$DOCKERFILE_PATH" -t "$IMAGE" "$BUILD_CONTEXT"

log "Docker push..."
docker push "$IMAGE"

log "Done: $IMAGE pushed to registry"
