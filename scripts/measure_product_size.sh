#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ARTIFACT="${1:-$ROOT_DIR/baby_mlkem768_product.o}"

if [[ "$ARTIFACT" != /* ]]; then
  ARTIFACT="$ROOT_DIR/$ARTIFACT"
fi
if [ ! -f "$ARTIFACT" ]; then
  echo "product artifact not found: $ARTIFACT" >&2
  exit 1
fi

for tool in objdump nm stat awk; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required tool not found: $tool" >&2
    exit 1
  fi
done

nm_output="$(nm -g --defined-only "$ARTIFACT")"
required_symbols=(
  baby_mlkem768_keypair_derand
  baby_mlkem768_encaps_derand
  baby_mlkem768_decaps
  baby_mlkem768_set_internal_caches_enabled
  baby_mlkem768_clear_internal_caches
)
for symbol in "${required_symbols[@]}"; do
  if ! awk -v target="$symbol" '$3 == target { found = 1 } END { exit !found }' \
      <<< "$nm_output"; then
    echo "required product symbol missing: $symbol" >&2
    exit 1
  fi
done

printf "artifact=%s\n" "$ARTIFACT"
printf "artifact_file_bytes=%s\n" "$(stat -c %s "$ARTIFACT")"

objdump -h "$ARTIFACT" | awk '
function hex_value(c) {
  if (c >= "0" && c <= "9") return c + 0
  c = tolower(c)
  return index("abcdef", c) + 9
}
function hex_to_dec(s, total, i) {
  total = 0
  for (i = 1; i <= length(s); i++) {
    total = 16 * total + hex_value(substr(s, i, 1))
  }
  return total
}
function account() {
  if (section == "" || flags !~ /ALLOC/) return
  bytes = hex_to_dec(hex_size)
  if (flags ~ /READONLY/) {
    if (section ~ /^\.note/ || section ~ /^\.eh_frame/ ||
        section ~ /^\.comment/ || section ~ /^\.debug/) return
    if (flags ~ /CODE/) code += bytes
    else readonly += bytes
  } else {
    if (flags ~ /CONTENTS/) initialized += bytes
    else zero_fill += bytes
  }
}
/^[[:space:]]*[0-9]+[[:space:]]+/ {
  account()
  section = $2
  hex_size = $3
  flags = ""
  next
}
section != "" { flags = flags " " $0 }
END {
  account()
  printf "code_bytes=%d\n", code
  printf "readonly_data_bytes=%d\n", readonly
  printf "primary_bytes=%d\n", code + readonly
  printf "initialized_writable_bytes=%d\n", initialized
  printf "zero_fill_bytes=%d\n", zero_fill
  printf "writable_bytes=%d\n", initialized + zero_fill
  printf "max_stack_bytes=unmeasured\n"
}
'
