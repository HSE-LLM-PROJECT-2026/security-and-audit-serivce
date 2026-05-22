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

CHART_DIR="${CHART_DIR:-$SCRIPT_DIR/helm/security-audit-service}"
VALUES_FILE="${VALUES_FILE:-$SCRIPT_DIR/values.security-audit-service.yaml}"
KUBECONFIG_PATH="${KUBECONFIG_PATH:-/home/oleg/Documents/hse-llm-project/cluster-config/llm_proj_talos/kubeconfig}"
NAMESPACE="${NAMESPACE:-${K8S_NAMESPACE:-hse-llm-project}}"
RELEASE_NAME="${RELEASE_NAME:-security-audit-service}"
IMAGE_REPOSITORY="${IMAGE_REPOSITORY:-awesomecosmonaut/security-audit-service}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"
POSTGRES_HOST="${POSTGRES_HOST:-postgresql.hse-llm-project.svc.cluster.local}"
POSTGRES_PORT="${POSTGRES_PORT:-5432}"
POSTGRES_DB="${POSTGRES_DB:-default}"
POSTGRES_USER="${POSTGRES_USER:-admin}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-admin}"
POSTGRES_SECRET_NAME="${POSTGRES_SECRET_NAME:-}"
POSTGRES_SECRET_KEY="${POSTGRES_SECRET_KEY:-}"
JWT_SECRET="${JWT_SECRET:-change-me}"
JWT_ALGORITHM="${JWT_ALGORITHM:-HS256}"
JWT_EXPIRATION_MINUTES="${JWT_EXPIRATION_MINUTES:-30}"
REFRESH_TOKEN_EXPIRATION_HOURS="${REFRESH_TOKEN_EXPIRATION_HOURS:-168}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@platform.local}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-admin}"
ADMIN_NAME="${ADMIN_NAME:-Platform Administrator}"
ADMIN_TEAM="${ADMIN_TEAM:-platform-admin}"
DEFAULT_USER_TEAM="${DEFAULT_USER_TEAM:-default}"
PROJECT_KEY="${PROJECT_KEY:-default}"
DEMO_USERS_ENABLED="${DEMO_USERS_ENABLED:-true}"
DEMO_USERS_PASSWORD="${DEMO_USERS_PASSWORD:-demo123}"
DEMO_SERVICE_ACCOUNT_API_KEY="${DEMO_SERVICE_ACCOUNT_API_KEY:-demo-ci-bot-api-key-platform-v2}"
CORS_ORIGINS="${CORS_ORIGINS:-*}"

log() {
  echo "[security-audit-service] $*"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "[security-audit-service] ERROR: command not found: $1" >&2
    exit 1
  }
}

log "Starting variables update"
log "Env file: $ENV_FILE"
log "Namespace: $NAMESPACE | Release: $RELEASE_NAME"
log "Chart dir: $CHART_DIR"
log "Values file: $VALUES_FILE"
log "Kubeconfig: $KUBECONFIG_PATH"
log "Image: $IMAGE_REPOSITORY:$IMAGE_TAG"

log "Checking required commands..."
need_cmd helm
need_cmd kubectl
log "Commands OK"

[[ -f "$KUBECONFIG_PATH" ]] || {
  echo "[security-audit-service] ERROR: kubeconfig not found: $KUBECONFIG_PATH" >&2
  exit 1
}

[[ -d "$CHART_DIR" ]] || {
  echo "[security-audit-service] ERROR: chart dir not found: $CHART_DIR" >&2
  exit 1
}

[[ -f "$VALUES_FILE" ]] || {
  echo "[security-audit-service] ERROR: values file not found: $VALUES_FILE" >&2
  exit 1
}

export KUBECONFIG="$KUBECONFIG_PATH"

log "Checking that release exists..."
if ! helm status "$RELEASE_NAME" -n "$NAMESPACE" >/dev/null 2>&1; then
  echo "[security-audit-service] ERROR: release '$RELEASE_NAME' not found in namespace '$NAMESPACE'" >&2
  echo "[security-audit-service] Run ./deploy-from-scratch.sh first" >&2
  exit 1
fi

log "Applying new values via helm upgrade..."
helm upgrade "$RELEASE_NAME" "$CHART_DIR" \
  --namespace "$NAMESPACE" \
  -f "$VALUES_FILE" \
  --set-string namespace.name="$NAMESPACE" \
  --set-string env.logLevel="$LOG_LEVEL" \
  --set-string env.jwtSecret="$JWT_SECRET" \
  --set-string env.jwtAlgorithm="$JWT_ALGORITHM" \
  --set-string env.jwtExpirationMinutes="$JWT_EXPIRATION_MINUTES" \
  --set-string env.refreshTokenExpirationHours="$REFRESH_TOKEN_EXPIRATION_HOURS" \
  --set-string env.adminEmail="$ADMIN_EMAIL" \
  --set-string env.adminPassword="$ADMIN_PASSWORD" \
  --set-string env.adminName="$ADMIN_NAME" \
  --set-string env.adminTeam="$ADMIN_TEAM" \
  --set-string env.defaultUserTeam="$DEFAULT_USER_TEAM" \
  --set-string env.projectKey="$PROJECT_KEY" \
  --set-string env.demoUsersEnabled="$DEMO_USERS_ENABLED" \
  --set-string env.demoUsersPassword="$DEMO_USERS_PASSWORD" \
  --set-string env.demoServiceAccountApiKey="$DEMO_SERVICE_ACCOUNT_API_KEY" \
  --set-string env.corsOrigins="$CORS_ORIGINS" \
  --set-string postgres.host="$POSTGRES_HOST" \
  --set-string postgres.port="$POSTGRES_PORT" \
  --set-string postgres.db="$POSTGRES_DB" \
  --set-string postgres.user="$POSTGRES_USER" \
  --set-string postgres.password="$POSTGRES_PASSWORD" \
  --set-string postgres.existingSecretName="$POSTGRES_SECRET_NAME" \
  --set-string postgres.existingSecretKey="$POSTGRES_SECRET_KEY" \
  --set-string image.repository="$IMAGE_REPOSITORY" \
  --set-string image.tag="$IMAGE_TAG"

log "Update finished. Current resources:"
kubectl get pods,svc -n "$NAMESPACE" -l "app.kubernetes.io/instance=$RELEASE_NAME"
