#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
COMPARATOR=liboqs exec \
  "$ROOT_DIR/scripts/verify_goal_comparator_size.sh" "$@"
