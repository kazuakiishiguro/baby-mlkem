#!/usr/bin/env bash
set -euo pipefail

PORT="${1:-8000}"
DOC_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
BIND_ADDR="${BIND_ADDR:-}"

if [[ -z "$BIND_ADDR" ]]; then
    if ! command -v tailscale >/dev/null 2>&1; then
        echo "tailscale コマンドが見つかりません。BIND_ADDR に Tailscale IP を指定してください。" >&2
        exit 1
    fi
    BIND_ADDR="$(tailscale ip -4 2>/dev/null | head -n 1 || true)"
fi

if [[ -z "$BIND_ADDR" ]]; then
    echo "Tailscale IP を取得できません。tailscaled を起動するか、次のように指定してください。" >&2
    echo "BIND_ADDR=100.x.y.z $0 $PORT" >&2
    exit 1
fi

echo "学習ガイド: http://${BIND_ADDR}:${PORT}/learning-journey.html"
echo "停止するには Ctrl-C を押してください。"
exec python3 -m http.server "$PORT" --bind "$BIND_ADDR" --directory "$DOC_DIR"
