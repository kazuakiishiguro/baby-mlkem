#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROFILE=native exec "$ROOT_DIR/scripts/verify_goal_speed.sh" "$@"
