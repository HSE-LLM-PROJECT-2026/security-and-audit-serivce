#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Thin wrapper for readability:
# removes security-audit-service Helm release from Kubernetes.
"$SCRIPT_DIR/delete-all.sh" "$@"
