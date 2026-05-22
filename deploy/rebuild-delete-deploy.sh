#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="$(basename "$(cd "$SCRIPT_DIR/.." && pwd)")"
SKIP_BUILD="${SKIP_BUILD:-false}"
APPLY_HTTPROUTE="${APPLY_HTTPROUTE:-true}"
STEP_TIMEOUT_SECONDS="${STEP_TIMEOUT_SECONDS:-7200}"
BUILD_TIMEOUT_SECONDS="${BUILD_TIMEOUT_SECONDS:-7200}"
DELETE_TIMEOUT_SECONDS="${DELETE_TIMEOUT_SECONDS:-1800}"
DEPLOY_TIMEOUT_SECONDS="${DEPLOY_TIMEOUT_SECONDS:-3600}"
NETWORK_TIMEOUT_SECONDS="${NETWORK_TIMEOUT_SECONDS:-1800}"
STEP_RETRY_ATTEMPTS="${STEP_RETRY_ATTEMPTS:-4}"
STEP_RETRY_DELAY_SECONDS="${STEP_RETRY_DELAY_SECONDS:-5}"
HELM_LOCK_CLEANUP_ON_RETRY="${HELM_LOCK_CLEANUP_ON_RETRY:-true}"

log() {
  echo "[${SERVICE_NAME}] $*"
}

require_script() {
  local script_path="$1"
  [[ -x "$script_path" ]] || {
    echo "[${SERVICE_NAME}] ERROR: script not found or not executable: $script_path" >&2
    exit 1
  }
}

is_helm_lock_error() {
  local lowered
  lowered="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  [[ "$lowered" == *"another operation (install/upgrade/rollback) is in progress"* ]]
}

is_retryable_output() {
  local lowered
  lowered="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  [[ "$lowered" == *"tls handshake timeout"* ]] \
    || [[ "$lowered" == *"unable to connect to the server"* ]] \
    || [[ "$lowered" == *"i/o timeout"* ]] \
    || [[ "$lowered" == *"context deadline exceeded"* ]] \
    || [[ "$lowered" == *"http2: client connection lost"* ]] \
    || [[ "$lowered" == *"client.timeout exceeded"* ]] \
    || [[ "$lowered" == *"connection reset by peer"* ]] \
    || [[ "$lowered" == *"timed out waiting for the condition"* ]] \
    || [[ "$lowered" == *"eof"* ]] \
    || [[ "$lowered" == *"another operation (install/upgrade/rollback) is in progress"* ]]
}

run_script_once() {
  local script_path="$1"
  local timeout_seconds="$2"
  local output_file="$3"
  if command -v timeout >/dev/null 2>&1; then
    timeout --foreground "${timeout_seconds}s" "$script_path" >"$output_file" 2>&1
  else
    "$script_path" >"$output_file" 2>&1
  fi
}

run_cleanup_before_retry() {
  local output_file=""
  local output=""
  local status=0
  if [[ "${HELM_LOCK_CLEANUP_ON_RETRY,,}" != "true" ]]; then
    return 0
  fi
  if [[ ! -x "$DELETE_SCRIPT" ]]; then
    return 0
  fi

  log "Detected Helm lock. Running cleanup step before deploy retry."
  output_file="$(mktemp)"
  if run_script_once "$DELETE_SCRIPT" "$DELETE_TIMEOUT_SECONDS" "$output_file"; then
    output="$(cat "$output_file" 2>/dev/null || true)"
    rm -f "$output_file"
    [[ -n "$output" ]] && printf '%s\n' "$output"
    return 0
  fi
  status=$?
  output="$(cat "$output_file" 2>/dev/null || true)"
  rm -f "$output_file"
  [[ -n "$output" ]] && printf '%s\n' "$output" >&2
  log "Cleanup step failed with exit code $status. Retrying deploy anyway."
  return 0
}

run_step() {
  local title="$1"
  local script_path="$2"
  local timeout_seconds="${3:-$STEP_TIMEOUT_SECONDS}"
  local phase="${4:-generic}"
  local attempt=1
  local output_file=""
  local output=""
  local status=0

  while ((attempt <= STEP_RETRY_ATTEMPTS)); do
    log "== $title (attempt $attempt/$STEP_RETRY_ATTEMPTS, timeout: ${timeout_seconds}s) =="
    output_file="$(mktemp)"
    if run_script_once "$script_path" "$timeout_seconds" "$output_file"; then
      output="$(cat "$output_file" 2>/dev/null || true)"
      rm -f "$output_file"
      [[ -n "$output" ]] && printf '%s\n' "$output"
      return 0
    fi

    status=$?
    output="$(cat "$output_file" 2>/dev/null || true)"
    rm -f "$output_file"
    [[ -n "$output" ]] && printf '%s\n' "$output" >&2

    if [[ "$phase" == "deploy" ]] && is_helm_lock_error "$output"; then
      run_cleanup_before_retry
    fi

    if ((attempt < STEP_RETRY_ATTEMPTS)) && { is_retryable_output "$output" || [[ "$status" -eq 124 ]]; }; then
      log "Retryable error in '$title'. Sleeping ${STEP_RETRY_DELAY_SECONDS}s before retry."
      sleep "$STEP_RETRY_DELAY_SECONDS"
      attempt=$((attempt + 1))
      continue
    fi
    return "$status"
  done
}

BUILD_SCRIPT="$SCRIPT_DIR/build-and-push.sh"
DELETE_SCRIPT="$SCRIPT_DIR/delete-all.sh"
DEPLOY_SCRIPT="$SCRIPT_DIR/deploy-from-scratch.sh"
NETWORK_SCRIPT="$SCRIPT_DIR/deploy-network.sh"

require_script "$DELETE_SCRIPT"
require_script "$DEPLOY_SCRIPT"

if [[ "$SKIP_BUILD" == "true" ]]; then
  log "== Skip build (SKIP_BUILD=true) =="
elif [[ -x "$BUILD_SCRIPT" ]]; then
  run_step "Build and push image" "$BUILD_SCRIPT" "$BUILD_TIMEOUT_SECONDS" "build"
else
  log "== Build step skipped: $BUILD_SCRIPT not found =="
fi

run_step "Delete current release" "$DELETE_SCRIPT" "$DELETE_TIMEOUT_SECONDS" "delete"
run_step "Deploy from scratch" "$DEPLOY_SCRIPT" "$DEPLOY_TIMEOUT_SECONDS" "deploy"

if [[ "$APPLY_HTTPROUTE" == "true" ]] && [[ -x "$NETWORK_SCRIPT" ]]; then
  run_step "Update HTTPRoute/network resources" "$NETWORK_SCRIPT" "$NETWORK_TIMEOUT_SECONDS" "network"
elif [[ "$APPLY_HTTPROUTE" != "true" ]]; then
  log "== Network step skipped (APPLY_HTTPROUTE=false) =="
else
  log "== Network step skipped: $NETWORK_SCRIPT not found =="
fi

log "Done: build -> delete -> deploy -> network update completed."
