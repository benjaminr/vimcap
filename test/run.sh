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

cat "$work/all.txt"
if grep -q '^FAIL' "$work/all.txt"; then
  exit 1
fi
echo "all tests passed"
