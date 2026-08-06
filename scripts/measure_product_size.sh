#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ARTIFACT="${1:-$ROOT_DIR/baby_mlkem768_product.o}"
DEFAULT_PRODUCT_SYMBOLS="baby_mlkem768_keypair_derand"
DEFAULT_PRODUCT_SYMBOLS+=" baby_mlkem768_encaps_derand"
DEFAULT_PRODUCT_SYMBOLS+=" baby_mlkem768_decaps"
DEFAULT_PRODUCT_SYMBOLS+=" baby_mlkem768_set_internal_caches_enabled"
DEFAULT_PRODUCT_SYMBOLS+=" baby_mlkem768_clear_internal_caches"

REQUIRED_SYMBOLS="${REQUIRED_SYMBOLS:-$DEFAULT_PRODUCT_SYMBOLS}" \
  exec "$ROOT_DIR/scripts/measure_elf_footprint.sh" "$ARTIFACT"
