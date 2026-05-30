#!/usr/bin/env bash
set -euo pipefail

ROOT_PATH="${PWD}"
SERVER_CMD=""
TOOL_NAME="get_project_structure"
TIMEOUT_SECS="10"

usage() {
  cat <<'EOF'
MCP handshake probe for NexusIntelliCore

Usage:
  scripts/mcp_handshake_probe.sh [options]

Options:
  --root <path>         Project root passed to MCP server (default: current dir)
  --server <path>       MCP server executable path
  --tool <name>         Tool name for tools/call (default: get_project_structure)
  --timeout <seconds>   Probe timeout in seconds (default: 10)
  -h, --help            Show this help

Examples:
  scripts/mcp_handshake_probe.sh
  scripts/mcp_handshake_probe.sh --server ./target/release/nexusintellicore
  scripts/mcp_handshake_probe.sh --tool tools/list
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --root)
      ROOT_PATH="$2"
      shift 2
      ;;
    --server)
      SERVER_CMD="$2"
      shift 2
      ;;
    --tool)
      TOOL_NAME="$2"
      shift 2
      ;;
    --timeout)
      TIMEOUT_SECS="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$SERVER_CMD" ]]; then
  if [[ -x "$ROOT_PATH/target/release/nexusintellicore" ]]; then
    SERVER_CMD="$ROOT_PATH/target/release/nexusintellicore"
  elif [[ -x "/Users/gasparoriol/Projects/MCP/nexusintellicore" ]]; then
    SERVER_CMD="/Users/gasparoriol/Projects/MCP/nexusintellicore"
  else
    echo "Could not auto-detect MCP server binary." >&2
    echo "Pass --server <path>." >&2
    exit 1
  fi
fi

if [[ ! -x "$SERVER_CMD" ]]; then
  echo "Server executable not found or not executable: $SERVER_CMD" >&2
  exit 1
fi

OUT_BIN="/tmp/nexus_mcp_probe_out.bin"
ERR_LOG="/tmp/nexus_mcp_probe_err.log"

if [[ "$TOOL_NAME" == "tools/list" ]]; then
  TOOL_REQUEST='{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
else
  TOOL_REQUEST='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"'"$TOOL_NAME"'","arguments":{}}}'
fi

INIT_REQUEST='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"mcp-probe","version":"1.0.0"}}}'
NOTIFY_REQUEST='{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}'

if command -v timeout >/dev/null 2>&1; then
  {
    for m in "$INIT_REQUEST" "$NOTIFY_REQUEST" "$TOOL_REQUEST"; do
      printf 'Content-Length: %s\r\n\r\n%s' "${#m}" "$m"
    done
  } | timeout "$TIMEOUT_SECS" "$SERVER_CMD" "$ROOT_PATH" > "$OUT_BIN" 2> "$ERR_LOG" || true
elif command -v gtimeout >/dev/null 2>&1; then
  {
    for m in "$INIT_REQUEST" "$NOTIFY_REQUEST" "$TOOL_REQUEST"; do
      printf 'Content-Length: %s\r\n\r\n%s' "${#m}" "$m"
    done
  } | gtimeout "$TIMEOUT_SECS" "$SERVER_CMD" "$ROOT_PATH" > "$OUT_BIN" 2> "$ERR_LOG" || true
else
  {
    for m in "$INIT_REQUEST" "$NOTIFY_REQUEST" "$TOOL_REQUEST"; do
      printf 'Content-Length: %s\r\n\r\n%s' "${#m}" "$m"
    done
  } | "$SERVER_CMD" "$ROOT_PATH" > "$OUT_BIN" 2> "$ERR_LOG" || true
fi

python3 - <<'PY'
import json
import re
from pathlib import Path

out_path = Path('/tmp/nexus_mcp_probe_out.bin')
err_path = Path('/tmp/nexus_mcp_probe_err.log')

raw = out_path.read_bytes() if out_path.exists() else b''
frames = []
i = 0

while True:
    j = raw.find(b'\r\n\r\n', i)
    if j == -1:
        break
    header = raw[i:j].decode('utf-8', 'replace')
    m = re.search(r'Content-Length:\s*(\d+)', header, re.IGNORECASE)
    if not m:
        break
    n = int(m.group(1))
    body_start = j + 4
    body_end = body_start + n
    if body_end > len(raw):
        break
    body = raw[body_start:body_end]
    try:
        frames.append(json.loads(body.decode('utf-8', 'replace')))
    except Exception as e:
        frames.append({'_parse_error': str(e), '_raw': body.decode('utf-8', 'replace')})
    i = body_end

print('MCP PROBE RESULT')
print('frames_received:', len(frames))

ok = True

if len(frames) < 1:
    ok = False
    print('FAIL: no response frames from server')
else:
    f1 = frames[0]
    if f1.get('id') != 1 or 'result' not in f1:
        ok = False
        print('FAIL: initialize response missing/invalid')
    else:
        proto = f1.get('result', {}).get('protocolVersion')
        if proto != '2024-11-05':
            ok = False
            print('FAIL: initialize protocolVersion mismatch:', proto)
        else:
            print('PASS: initialize response is valid')

if len(frames) < 2:
    ok = False
    print('FAIL: second frame missing (expected tools response)')
else:
    f2 = frames[1]
    if f2.get('id') != 2 or 'result' not in f2:
        ok = False
        print('FAIL: tools response missing/invalid')
    else:
        print('PASS: tools response received')

print('')
print('Decoded frames:')
for idx, f in enumerate(frames, 1):
    print(f'--- frame {idx} ---')
    print(json.dumps(f, ensure_ascii=False, indent=2)[:8000])

if err_path.exists() and err_path.stat().st_size > 0:
    print('')
    print('Server stderr (tail):')
    lines = err_path.read_text(errors='replace').splitlines()
    for line in lines[-20:]:
        print(line)

if not ok:
    raise SystemExit(2)
PY
