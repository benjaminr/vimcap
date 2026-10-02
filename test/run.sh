#!/usr/bin/env bash
# Integration test: generates a capture, drives headless Vim through the
# plugin, and verifies byte-level round trips with Python.
#
# Usage: VIMCAP_PYTHON=/path/to/python test/run.sh
# (the interpreter must have scapy installed)

set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(dirname "$here")"
python="${VIMCAP_PYTHON:-python3}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

"$python" - "$work/sample.pcap" <<'PYEOF'
import sys
from scapy.all import DNS, IP, TCP, UDP, Ether, Raw, wrpcap

packets = [
    Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
    / IP(src="10.0.0.1", dst="10.0.0.2")
    / TCP(sport=1234, dport=80)
    / Raw(b"GET / HTTP/1.1\r\n"),
    Ether() / IP(dst="8.8.8.8") / UDP(sport=5353, dport=53) / DNS(rd=1),
]
packets[0].time = 1700000000.123456
packets[1].time = 1700000001.654321
wrpcap(sys.argv[1], packets)
PYEOF
cp "$work/sample.pcap" "$work/original.pcap"

VIMCAP_TEST_OUT="$work/results.txt" VIMCAP_TEST_DIR="$work" \
  vim -N -u NONE -i NONE -n -es \
  --cmd "set runtimepath^=$root" \
  --cmd "runtime plugin/vimcap.vim" \
  --cmd "let g:vimcap_python='$python'" \
  -c "source $here/test.vim" \
  -- "$work/sample.pcap" >/dev/null 2>&1 || true

if [[ ! -f "$work/results.txt" ]] || ! grep -q '^DONE$' "$work/results.txt"; then
  echo "FAIL: vim test did not complete"
  cat "$work/results.txt" 2>/dev/null || true
  exit 1
fi
grep -v '^DONE$' "$work/results.txt" > "$work/all.txt"

# Unedited save must be byte-identical to the original capture.
if cmp -s "$work/original.pcap" "$work/roundtrip.pcap"; then
  echo "ok   unedited save is byte-identical" >> "$work/all.txt"
else
  echo "FAIL unedited save differs from original" >> "$work/all.txt"
fi

# The MCP agent bridge: handshake, tool listing, and a tool call forwarded
# to a fake Vim over the channel socket.
"$python" - "$root/python/vimcap.py" "$work/agent-session.json" >> "$work/all.txt" <<'PYEOF'
import json, socket, subprocess, sys, time

script, session = sys.argv[1], sys.argv[2]
server = subprocess.Popen([sys.executable, script, "mcp", "--session", session],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

def rpc(method, params=None, request_id=None):
    message = {"jsonrpc": "2.0", "method": method, "params": params or {}}
    if request_id is not None:
        message["id"] = request_id
    server.stdin.write(json.dumps(message) + "\n")
    server.stdin.flush()
    return json.loads(server.stdout.readline()) if request_id is not None else None

init = rpc("initialize", {"protocolVersion": "2024-11-05"}, 1)
ok = init["result"]["serverInfo"]["name"] == "vimcap"
print(("ok   " if ok else "FAIL ") + "mcp server initialises")

tools = rpc("tools/list", {}, 2)["result"]["tools"]
names = {tool["name"] for tool in tools}
ok = {"overview", "goto", "set_field", "filter"} <= names
print(("ok   " if ok else "FAIL ") + f"mcp server lists {len(tools)} tools")

for _ in range(50):
    try:
        info = json.load(open(session))
        break
    except Exception:
        time.sleep(0.1)
fake_vim = socket.create_connection(("127.0.0.1", info["port"]))
fake_vim.sendall((json.dumps([-1, {"auth": info["token"]}]) + "\n").encode())
auth_reply = json.loads(fake_vim.recv(4096))
ok = auth_reply == [-1, "ok"]
print(("ok   " if ok else "FAIL ") + "vim channel authenticates with the token")

# tools/call only answers after vim replies, so write it without reading.
server.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
    "params": {"name": "overview", "arguments": {}}}) + "\n")
server.stdin.flush()
forwarded = json.loads(fake_vim.recv(4096))
ok = forwarded[:3] == ["call", "vimcap#agent#dispatch", ["overview", {}]]
print(("ok   " if ok else "FAIL ") + "tool call is forwarded to vim")
fake_vim.sendall((json.dumps([forwarded[3], {"packet_count": 7}]) + "\n").encode())
result = json.loads(server.stdout.readline())
ok = "packet_count" in result["result"]["content"][0]["text"]
print(("ok   " if ok else "FAIL ") + "tool result returns to the agent")

# A tool call in flight when Vim disconnects must get an error, not hang.
server.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
    "params": {"name": "overview", "arguments": {}}}) + "\n")
server.stdin.flush()
fake_vim.recv(4096)        # the forwarded call
fake_vim.close()           # Vim goes away without answering
import select as _select
ready, _, _ = _select.select([server.stdout], [], [], 5)
if ready:
    reply = json.loads(server.stdout.readline())
    ok = reply.get("id") == 4 and reply["result"].get("isError")
    print(("ok   " if ok else "FAIL ") + "in-flight call errors when vim disconnects")
else:
    print("FAIL in-flight call hangs when vim disconnects")

server.stdin.close(); server.terminate()
PYEOF

# The edited save must contain the new ttl byte but keep the timestamp.
"$python" - "$work/sample.pcap" >> "$work/all.txt" <<'PYEOF'
import sys
from scapy.all import rdpcap

packets = rdpcap(sys.argv[1])
ttl_ok = packets[0].ttl == 255
time_ok = str(packets[0].time) == "1700000000.123456"
print(("ok   " if ttl_ok else "FAIL ") + f"edited ttl persisted (ttl={packets[0].ttl})")
print(("ok   " if time_ok else "FAIL ") + f"timestamp preserved ({packets[0].time})")
PYEOF

# The pure-Python path (no scapy) must still round-trip byte-identically.
# Only runs when an interpreter without scapy is available.
noscapy=""
for candidate in python3 python; do
  if command -v "$candidate" >/dev/null 2>&1 && \
     ! "$candidate" -c 'import scapy' >/dev/null 2>&1; then
    noscapy="$candidate"
    break
  fi
done
if [[ -n "$noscapy" ]]; then
  "$noscapy" "$root/python/vimcap.py" load "$work/original.pcap" \
    --meta "$work/ns.json" > "$work/ns.hex" 2>/dev/null
  "$noscapy" "$root/python/vimcap.py" save "$work/ns.pcap" \
    --meta "$work/ns.json" < "$work/ns.hex" >/dev/null 2>&1
  if cmp -s "$work/original.pcap" "$work/ns.pcap"; then
    echo "ok   pure-Python path round-trips byte-identically (no scapy)" >> "$work/all.txt"
  else
    echo "FAIL pure-Python path does not round-trip without scapy" >> "$work/all.txt"
  fi
  if echo '{"op":"show","hex":"aabb","linktype":1}' \
     | "$noscapy" "$root/python/vimcap.py" rpc 2>/dev/null | grep -q '"error"'; then
    echo "ok   dissection ops error gracefully without scapy" >> "$work/all.txt"
  else
    echo "FAIL dissection ops do not degrade gracefully without scapy" >> "$work/all.txt"
  fi
else
  echo "ok   (no scapy-free interpreter available; skipped pure-Python checks)" >> "$work/all.txt"
fi

cat "$work/all.txt"
if grep -q '^FAIL' "$work/all.txt"; then
  exit 1
fi
echo "all tests passed"
