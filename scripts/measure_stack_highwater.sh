#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ARTIFACT="${1:-}"
API_KIND="${2:-}"
RUNS="${STACK_RUNS:-8}"
USABLE_BYTES="${STACK_USABLE_BYTES:-1048576}"
C_COMPILER="${C_COMPILER:-clang}"
STACK_CFLAGS="${STACK_CFLAGS:--O2 -march=native -fomit-frame-pointer -fno-stack-protector}"
STACK_LINKER="${STACK_LINKER:-$C_COMPILER}"
STACK_LDFLAGS="${STACK_LDFLAGS:-}"

if [ -z "$ARTIFACT" ] || [[ ! "$API_KIND" =~ ^(local|goal)$ ]]; then
  echo "usage: $0 ARTIFACT local|goal" >&2
  exit 2
fi
if [[ "$ARTIFACT" != /* ]]; then
  ARTIFACT="$ROOT_DIR/$ARTIFACT"
fi
if [ ! -f "$ARTIFACT" ]; then
  echo "artifact not found: $ARTIFACT" >&2
  exit 2
fi
if [ "$(uname -m)" != "x86_64" ]; then
  echo "stack high-water probe currently requires x86_64" >&2
  exit 2
fi
if ! [[ "$RUNS" =~ ^[1-9][0-9]*$ ]] ||
    ! [[ "$USABLE_BYTES" =~ ^[1-9][0-9]*$ ]]; then
  echo "STACK_RUNS and STACK_USABLE_BYTES must be positive integers" >&2
  exit 2
fi
for tool in "$C_COMPILER" "$STACK_LINKER" awk sha256sum; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "required tool not found: $tool" >&2
    exit 2
  fi
done

work_dir="$(mktemp -d /tmp/baby-mlkem-stack.XXXXXX)"
trap 'rm -rf "$work_dir"' EXIT
read -r -a stack_cflags_arr <<< "$STACK_CFLAGS"
read -r -a stack_ldflags_arr <<< "$STACK_LDFLAGS"
defines=()
if [ "$API_KIND" = local ]; then
  defines=(-DGOAL_LOCAL_PRODUCT -I"$ROOT_DIR")
else
  defines=(-I"$ROOT_DIR/scripts")
fi

"$C_COMPILER" "${stack_cflags_arr[@]}" "${defines[@]}" \
  -c "$ROOT_DIR/scripts/goal_stack_probe.c" \
  -o "$work_dir/goal_stack_probe.o"
"$C_COMPILER" -c "$ROOT_DIR/scripts/goal_stack_switch_x86_64.S" \
  -o "$work_dir/goal_stack_switch_x86_64.o"
"$STACK_LINKER" "${stack_cflags_arr[@]}" \
  "$work_dir/goal_stack_probe.o" "$work_dir/goal_stack_switch_x86_64.o" \
  "$ARTIFACT" "${stack_ldflags_arr[@]}" -Wl,-z,noexecstack \
  -o "$work_dir/stack_probe"

printf "artifact=%s\n" "$ARTIFACT"
printf "artifact_sha256=%s\n" "$(sha256sum "$ARTIFACT" | awk '{print $1}')"
printf "api_kind=%s\n" "$API_KIND"
printf "compiler=%s\n" "$C_COMPILER"
printf "stack_cflags=%s\n" "$STACK_CFLAGS"
printf "stack_linker=%s\n" "$STACK_LINKER"
printf "stack_ldflags=%s\n" "${STACK_LDFLAGS:-<none>}"
"$work_dir/stack_probe" "$RUNS" "$USABLE_BYTES"
