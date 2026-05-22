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

KUBECONFIG_PATH="${KUBECONFIG_PATH:-/home/oleg/Documents/hse-llm-project/cluster-config/llm_proj_talos/kubeconfig}"
NAMESPACE="${NAMESPACE:-${K8S_NAMESPACE:-hse-llm-project}}"
HTTPROUTE_NAME="${HTTPROUTE_NAME:-security-audit-route}"
HTTPROUTE_FILE="${HTTPROUTE_FILE:-$SCRIPT_DIR/network/httproute-security-audit.yaml}"
HTTPROUTE_NAMESPACE="${HTTPROUTE_NAMESPACE:-$NAMESPACE}"

log() {
  echo "[security-audit-service] $*"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[security-audit-service] ERROR: command not found: $1" >&2
    exit 1
  }
}

need_cmd kubectl

[[ -f "$KUBECONFIG_PATH" ]] || {
  echo "[security-audit-service] ERROR: kubeconfig not found: $KUBECONFIG_PATH" >&2
  exit 1
}

[[ -f "$HTTPROUTE_FILE" ]] || {
  echo "[security-audit-service] ERROR: HTTPRoute file not found: $HTTPROUTE_FILE" >&2
  exit 1
}

export KUBECONFIG="$KUBECONFIG_PATH"

log "Applying HTTPRoute manifest: $HTTPROUTE_FILE"
kubectl apply -f "$HTTPROUTE_FILE"

log "HTTPRoute status:"
kubectl -n "$HTTPROUTE_NAMESPACE" get httproute "$HTTPROUTE_NAME"
