#!/usr/bin/env python3
"""Helper script for vimcap: converts packet captures to and from editable hex.

Invoked by the Vim plugin, never directly by users. Each subcommand reads
hex lines on stdin and/or a capture file, and communicates annotations
(timestamps, link type, per-field byte offsets) through a JSON "meta" file
so that saving a buffer round-trips the original capture faithfully.
"""

from __future__ import annotations  # scapy types in signatures stay unevaluated

import argparse
import json
import logging
import struct
import sys
from decimal import Decimal
from pathlib import Path


def fail(message: str) -> None:
    """Report a fatal error to the plugin and exit non-zero."""
    print(f"vimcap: {message}", file=sys.stderr)
    sys.exit(1)


def warn(message: str) -> None:
    """Report a non-fatal warning; the plugin echoes lines mentioning vimcap."""
    print(f"vimcap: {message}", file=sys.stderr)


# Keep scapy's chatter out of stderr: the plugin treats stderr as warnings.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

# scapy is optional: without it the hex editor still opens, edits and saves
# captures byte-faithfully through the pure-Python pcap reader/writer below;
# scapy only unlocks dissection (colours, the field inspector, and the
# filter/follow/stats/craft toolbox).
try:
    import scapy.all  # noqa: F401  (registers every protocol layer)
    from scapy.compat import raw
    from scapy.config import conf
    from scapy.packet import NoPayload, Packet, Raw
    from scapy.utils import PcapReader, RawPcapWriter

    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


def require_scapy(feature: str = "this operation") -> None:
    """Abort with a helpful message when a scapy-only feature is requested."""
    if not HAS_SCAPY:
        fail(f"{feature} needs scapy (pip install scapy, or run the plugin's "
             "install.sh); the hex editor works without it")

MAX_FIELD_VALUE_LEN = 48
DEFAULT_LINKTYPE = 1  # DLT_EN10MB (Ethernet)
PAYLOAD_LAYERS = {"Raw", "Padding"}


# --- pure-Python classic-pcap I/O (the no-scapy round-trip path) -----------

PCAP_GLOBAL_HEADER = struct.Struct("<IHHIIII")  # magic, maj, min, zone, sig, snap, net
PCAP_RECORD_HEADER = struct.Struct("<IIII")     # ts_sec, ts_frac, caplen, origlen


def native_read(path):
    """Read a classic pcap without scapy.

    Returns (linktype, datas, times, wirelens). Raises ValueError on anything
    that is not classic pcap (e.g. pcapng), which still requires scapy.
    """
    blob = Path(path).read_bytes()
    if len(blob) < 24:
        raise ValueError("file too short to be a pcap")
    magic = blob[:4]
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\x4d\x3c\xb2\xa1": "<",
              b"\xa1\xb2\xc3\xd4": ">", b"\xa1\xb2\x3c\x4d": ">"}.get(magic)
    if endian is None:
        raise ValueError("not a classic pcap file (pcapng requires scapy)")
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    header = struct.Struct(endian + "IHHIIII")
    record = struct.Struct(endian + "IIII")
    linktype = header.unpack_from(blob, 0)[6]

    datas, times, wirelens = [], [], []
    offset = 24
    while offset + record.size <= len(blob):
        ts_sec, ts_frac, caplen, origlen = record.unpack_from(blob, offset)
        offset += record.size
        datas.append(blob[offset:offset + caplen])
        offset += caplen
        times.append(f"{ts_sec}.{ts_frac:0{9 if nano else 6}d}")
        wirelens.append(origlen)
    return linktype, datas, times, wirelens


def native_write(path, linktype, records) -> None:
    """Write a classic pcap without scapy, matching scapy's global header.

    `records` is an iterable of (data, sec, usec, wirelen). The header is the
    same microsecond-resolution, 65535-snaplen form scapy's writer emits, so
    output is byte-identical to the scapy path for scapy-written inputs.
    """
    out = bytearray(PCAP_GLOBAL_HEADER.pack(0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
    for data, sec, usec, wirelen in records:
        out += PCAP_RECORD_HEADER.pack(sec, usec, len(data), wirelen)
        out += data
    Path(path).write_bytes(out)


def packet_record(times, wirelens, index, data):
    """Resolve one packet's (sec, usec, wirelen) for writing."""
    stamp = Decimal(time_at(times, index))
    seconds = int(stamp)
    microseconds = int((stamp - seconds) * 1_000_000)
    return seconds, microseconds, wirelen_at(wirelens, index, len(data))


def parse_hex_lines(lines) -> list:
    """Convert buffer lines of space-separated hex into packet byte strings.

    Blank lines are skipped so deleting a packet leaves no residue.
    """
    packets = []
    for lineno, line in enumerate(lines, start=1):
        cleaned = line.strip().replace(" ", "")
        if not cleaned:
            continue
        try:
            packets.append(bytes.fromhex(cleaned))
        except ValueError:
            fail(f"line {lineno} is not valid hex (check for stray characters)")
    return packets


def linktype_class(linktype: int):
    """Return the scapy layer class used to dissect a given link type."""
    return conf.l2types.num2layer.get(linktype, Raw)


def resolve_protocol(name: str):
    """Look up a scapy protocol class by name, e.g. 'IP' or 'DNS'."""
    import scapy.all

    cls = getattr(scapy.all, name, None)
    if not (isinstance(cls, type) and issubclass(cls, Packet)):
        fail(f"'{name}' is not a known scapy protocol")
    return cls


def dissect(data: bytes, linktype: int, proto=None) -> Packet:
    """Dissect raw bytes, falling back to Raw if scapy cannot parse them."""
    cls = resolve_protocol(proto) if proto else linktype_class(linktype)
    try:
        return cls(data)
    except Exception:
        return Raw(data)


def _bits_left(state) -> int:
    """Bits not yet consumed by getfield; state may be bytes or (bytes, used)."""
    if isinstance(state, tuple):
        data, used_bits = state
        return len(data) * 8 - used_bits
    return len(state) * 8


def _format_value(value) -> str:
    text = str(value)
    if len(text) > MAX_FIELD_VALUE_LEN:
        text = text[: MAX_FIELD_VALUE_LEN - 1] + "…"
    return text


def printable(data: bytes, separator: str = "") -> str:
    """Render bytes as printable ASCII, non-printables shown as '.'."""
    return separator.join(chr(b) if 32 <= b < 127 else "." for b in data)


def layer_and_field_ranges(packet: Packet):
    """Compute absolute byte ranges for every layer and field of a packet.

    Returns (layers, fields) where each layer is [start, end, name] and each
    field is [start, end, layer_name, field_name, value]. Field offsets are
    recovered by replaying each layer's field parsers over its own bytes,
    which also handles bit-packed fields sharing a byte.
    """
    layers = []
    fields = []
    base = 0
    for current in walk_layers(packet):
        layer_bytes = raw(current)
        payload_len = len(raw(current.payload)) if current.payload else 0
        header_len = len(layer_bytes) - payload_len
        # A layer with a payload owns only its header bytes; the final layer
        # (typically Raw) owns everything that remains.
        layer_len = header_len if payload_len else len(layer_bytes)
        layers.append([base, base + layer_len, current.name])

        total_bits = len(layer_bytes) * 8
        state = layer_bytes
        for field in current.fields_desc:
            try:
                start_bit = total_bits - _bits_left(state)
                state, _ = field.getfield(current, state)
                end_bit = total_bits - _bits_left(state)
            except Exception:
                break
            start_byte = start_bit // 8
            end_byte = (end_bit + 7) // 8
            if end_byte <= start_byte or start_byte >= len(layer_bytes):
                continue
            value = _format_value(current.getfieldval(field.name))
            if field.name in ("src", "dst") and current.name == "Ethernet":
                vendor = mac_vendor(value)
                if vendor:
                    value += f" ({vendor})"
            fields.append(
                [base + start_byte, base + end_byte, current.name, field.name, value]
            )
        base += header_len
    return layers, fields


FIXABLE_FIELDS = ("chksum", "cksum", "len", "plen")


def walk_layers(packet: Packet):
    """Yield each layer of a packet's payload chain."""
    current = packet
    while isinstance(current, Packet) and not isinstance(current, NoPayload):
        yield current
        current = current.payload


def fix_bytes(data: bytes, linktype: int, keep=None) -> bytes:
    """Rebuild a packet with checksums and length fields recomputed.

    Deleting a dissected field resets it to its default, and scapy fills
    checksum/length defaults in while rebuilding. `keep` is an optional
    (layer, field_name) left untouched, for when a user sets one by hand.
    """
    packet = dissect(data, linktype)
    for layer in walk_layers(packet):
        for name in FIXABLE_FIELDS:
            if (layer, name) != (keep or (None, None)) and name in layer.fields:
                try:
                    delattr(layer, name)
                except Exception:
                    pass
    try:
        return raw(packet)
    except Exception:
        return data


def bad_checksums(data: bytes, linktype: int, original=None) -> list:
    """Names of checksum fields that do not match their recomputed values.

    Pass `original` (an already-dissected packet) to avoid re-dissecting when
    the caller has one to hand.
    """
    try:
        if original is None:
            original = dissect(data, linktype)
        rebuilt = dissect(fix_bytes(data, linktype), linktype)
    except Exception:
        return []
    bad = []
    for ours, theirs in zip(walk_layers(original), walk_layers(rebuilt)):
        for name in ("chksum", "cksum"):
            if name in [f.name for f in ours.fields_desc]:
                try:
                    if ours.getfieldval(name) != theirs.getfieldval(name):
                        bad.append(f"{ours.name}.{name}")
                except Exception:
                    pass
    return bad


def mac_vendor(mac: str):
    """Short vendor name for a MAC address, when scapy's manuf db knows it."""
    try:
        vendor = conf.manufdb._get_short_manuf(mac)
        return vendor if vendor and vendor != mac else None
    except Exception:
        return None


def scapy_namespace() -> dict:
    """The namespace scapy expressions evaluate in.

    `__builtins__` is emptied so expressions reach scapy's names but not
    `__import__`, `open`, `eval` and friends. This blocks the obvious escapes
    (the agent is deliberately scoped to the vimcap tools) but is a restriction,
    not a hardened sandbox — a determined expression can still reach dangerous
    attributes through object traversal, so expression evaluation remains a
    trusted operation, not an untrusted-input boundary.
    """
    import scapy.all

    namespace = {name: getattr(scapy.all, name) for name in dir(scapy.all)}
    namespace["__builtins__"] = {}
    return namespace


def set_field(data: bytes, linktype: int, spec: str) -> bytes:
    """Apply a 'field=value' or 'Layer.field=value' edit to packet bytes."""
    name, separator, value_text = spec.partition("=")
    if not separator or not name.strip():
        raise ValueError(f"expected field=value, got {spec!r}")
    name, value_text = name.strip(), value_text.strip()
    layer_name, _, field_name = name.rpartition(".")

    packet = dissect(data, linktype)
    target = None
    for layer in walk_layers(packet):
        names = {layer.name.lower(), type(layer).__name__.lower()}
        if layer_name and layer_name.lower() not in names:
            continue
        if field_name in [f.name for f in layer.fields_desc]:
            target = layer
            break
    if target is None:
        raise ValueError(f"no layer with a field called {name!r}")

    try:
        value = int(value_text, 0)
    except ValueError:
        value = value_text.strip("'\"")
    setattr(target, field_name, value)
    return fix_bytes(raw(packet), linktype, keep=(target, field_name))


def filter_indices(datas, linktype, expr):
    """1-based indices of packets matching a layer name or Python expression."""
    namespace = scapy_namespace()
    bare = namespace.get(expr.strip())
    matches, first_error = [], None
    for index, data in enumerate(datas, start=1):
        packet = dissect(data, linktype)
        try:
            if isinstance(bare, type) and issubclass(bare, Packet):
                matched = packet.haslayer(bare)
            else:
                matched = bool(eval(expr, namespace, {"p": packet, "pkt": packet}))
        except Exception as error:
            first_error = first_error or error
            matched = False
        if matched:
            matches.append(index)
    if not matches and first_error is not None:
        raise ValueError(f"filter failed: {first_error}")
    return matches


def network_layer(packet: Packet):
    """The IP/IPv6 layer of a packet, or None."""
    from scapy.all import IP, IPv6

    return packet.getlayer(IP) or packet.getlayer(IPv6)


def transport_layer(packet: Packet):
    """The TCP/UDP layer of a packet, or None."""
    from scapy.all import TCP, UDP

    return packet.getlayer(TCP) or packet.getlayer(UDP)


def session_key(packet: Packet):
    """Bidirectional conversation key, or None for sessionless packets."""
    network = network_layer(packet)
    transport = transport_layer(packet)
    if network is None or transport is None:
        return None
    ends = sorted([(network.src, transport.sport), (network.dst, transport.dport)])
    return (type(transport).__name__, tuple(ends))


def follow_stream(datas, linktype, index):
    """Packets in the same conversation as packet `index`, plus its payloads."""
    packets = [dissect(data, linktype) for data in datas]
    wanted = session_key(packets[index - 1])
    if wanted is None:
        raise ValueError("packet has no TCP/UDP conversation to follow")
    first_source = None
    indices, lines = [], [f"{wanted[0]} {wanted[1][0]} <> {wanted[1][1]}", ""]
    for position, packet in enumerate(packets, start=1):
        if session_key(packet) != wanted:
            continue
        indices.append(position)
        transport = transport_layer(packet)
        payload = raw(transport.payload)
        if not payload:
            continue
        source = packet.payload.src if hasattr(packet.payload, "src") else ""
        if first_source is None:
            first_source = source
        arrow = "->" if source == first_source else "<-"
        for text_line in payload.decode("utf-8", errors="replace").splitlines():
            lines.append(f"{arrow} {text_line}")
    return indices, lines


def grep_payloads(datas, pattern):
    """(index, byte offset, printable context) for each regex match."""
    import re

    regex = re.compile(pattern.encode("utf-8", errors="ignore"))
    matches = []
    for index, data in enumerate(datas, start=1):
        for match in regex.finditer(data):
            context = data[match.start():match.start() + 32]
            matches.append([index, match.start(), printable(context)])
    return matches


def capture_stats(datas, linktype, times):
    """Human-readable overview of the capture."""
    from collections import Counter

    stacks, talkers, ports = Counter(), Counter(), Counter()
    total_bytes = 0
    for data in datas:
        total_bytes += len(data)
        packet = dissect(data, linktype)
        stacks[" / ".join(l.name for l in walk_layers(packet))] += 1
        network = network_layer(packet)
        if network is not None:
            talkers[f"{network.src} -> {network.dst}"] += 1
        transport = transport_layer(packet)
        if transport is not None:
            ports[f"{type(transport).__name__} {transport.dport}"] += 1

    duration = ""
    if len(times) >= 2:
        try:
            span = Decimal(times[-1]) - Decimal(times[0])
            duration = f" over {span}s"
        except Exception:
            pass
    lines = [f"{len(datas)} packets, {total_bytes} bytes{duration}", ""]
    for title, counter in (("Protocols", stacks), ("Conversations", talkers),
                           ("Ports", ports)):
        lines.append(title)
        for key, count in counter.most_common(10):
            lines.append(f"  {count:5d}  {key}")
        lines.append("")
    return lines


def anonymise(datas, linktype):
    """Consistently rewrite MAC and IP addresses across the capture.

    Payload contents (DNS names, HTTP hosts, ...) are left alone; checksums
    are recomputed. The mapping is per-run, so repeat runs differ.
    """
    from scapy.all import ARP, IP, IPv6, Ether

    macs, ips = {}, {}

    def new_mac(mac):
        if mac not in macs:
            macs[mac] = f"02:00:00:00:00:{len(macs) + 1:02x}"
        return macs[mac]

    def new_ip(address):
        if address not in ips:
            count = len(ips) + 1
            ips[address] = (
                f"fd00::{count:x}" if ":" in address
                else f"10.99.{count // 256}.{count % 256}"
            )
        return ips[address]

    results = []
    for data in datas:
        packet = dissect(data, linktype)
        for layer in walk_layers(packet):
            if isinstance(layer, Ether):
                layer.src, layer.dst = new_mac(layer.src), new_mac(layer.dst)
            elif isinstance(layer, (IP, IPv6)):
                layer.src, layer.dst = new_ip(layer.src), new_ip(layer.dst)
            elif isinstance(layer, ARP):
                layer.hwsrc, layer.hwdst = new_mac(layer.hwsrc), new_mac(layer.hwdst)
                layer.psrc, layer.pdst = new_ip(layer.psrc), new_ip(layer.pdst)
        results.append(fix_bytes(raw(packet), linktype))
    return results


def time_at(times, index) -> str:
    """Timestamp for a packet, carrying the last known value forward."""
    if index < len(times):
        return times[index]
    return times[-1] if times else "0"


def wirelen_at(wirelens, index, data_len, trust=False) -> int:
    """Wire length for a packet; falls back to the captured length.

    A stored wire length larger than the data is only honoured when `trust`
    is set (i.e. it came straight from a capture file and the packet was
    genuinely wire-truncated). On the edit path the current byte count is
    authoritative, so shortening a packet no longer leaves it looking
    wire-truncated.
    """
    if trust and index < len(wirelens) and data_len <= wirelens[index]:
        return wirelens[index]
    return data_len


def annotate(datas, linktype, limit, times, wirelens, trust_wirelens=False):
    """Build the meta structure for a list of packet byte strings."""
    entries = []
    for index, data in enumerate(datas):
        entry = {
            "t": time_at(times, index),
            "wl": wirelen_at(wirelens, index, len(data), trust=trust_wirelens),
        }
        if index < limit and HAS_SCAPY:
            packet = dissect(data, linktype)
            try:
                entry["s"] = packet.summary()
                entry["layers"], entry["fields"] = layer_and_field_ranges(packet)
                entry["bad"] = bad_checksums(data, linktype, original=packet)
            except Exception:
                entry["s"] = f"Raw ({len(data)} bytes)"
                entry["layers"] = [[0, len(data), "Raw"]]
                entry["fields"] = []
        entries.append(entry)
    return {"linktype": linktype, "packets": entries}


def read_meta(path):
    """Load an existing meta file; returns None when absent or unreadable."""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def write_meta(path, meta) -> None:
    Path(path).write_text(json.dumps(meta, separators=(",", ":")), encoding="utf-8")


def carried_times_and_wirelens(meta):
    """Extract per-packet timestamps and wire lengths from an old meta file."""
    if not meta:
        return [], []
    packets = meta.get("packets", [])
    return [p.get("t", "0") for p in packets], [p.get("wl", 0) for p in packets]


def cmd_load(args) -> None:
    """Read a capture file, print hex lines, and write the meta sidecar."""
    try:
        if HAS_SCAPY:
            with PcapReader(args.path) as reader:
                packets = list(reader)
            linktype = getattr(reader, "linktype", None)
            if linktype is None:
                # pcapng stores link types per interface; recover it from the
                # first dissected packet's class, defaulting to Ethernet.
                first_cls = packets[0].__class__ if packets else None
                linktype = conf.l2types.layer2num.get(first_cls, DEFAULT_LINKTYPE)
            datas = [raw(p) for p in packets]
            times = [str(p.time) for p in packets]
            wirelens = [getattr(p, "wirelen", None) or len(d)
                        for p, d in zip(packets, datas)]
        else:
            linktype, datas, times, wirelens = native_read(args.path)
    except Exception as error:
        fail(f"could not read {args.path}: {error}")

    meta = annotate(datas, linktype, args.limit, times, wirelens, trust_wirelens=True)
    write_meta(args.meta, meta)
    sys.stdout.write("\n".join(data.hex(" ") for data in datas))
    if datas:
        sys.stdout.write("\n")


def cmd_save(args) -> None:
    """Write buffer hex back to a capture, preserving timestamps and link type."""
    datas = parse_hex_lines(sys.stdin)
    old_meta = read_meta(args.meta) if args.meta else None
    linktype = (old_meta or {}).get("linktype", args.linktype)
    times, wirelens = carried_times_and_wirelens(old_meta)

    if Path(args.path).suffix.lower() in {".pcapng", ".ntar"}:
        warn("saved in classic pcap format (pcapng writing is not supported)")

    temp_path = args.path + ".vimcap.tmp"
    try:
        if HAS_SCAPY:
            writer = RawPcapWriter(temp_path, linktype=linktype, sync=True)
            writer.write_header(None)
            for index, data in enumerate(datas):
                seconds, microseconds, wirelen = packet_record(
                    times, wirelens, index, data)
                writer.write_packet(data, sec=seconds, usec=microseconds,
                                    wirelen=wirelen)
            writer.close()
        else:
            native_write(temp_path, linktype, (
                (data,) + packet_record(times, wirelens, index, data)
                for index, data in enumerate(datas)))
        Path(temp_path).replace(args.path)
    except OSError as error:
        fail(f"could not write {args.path}: {error}")

    if args.meta:
        write_meta(args.meta, annotate(datas, linktype, args.limit, times, wirelens))
    print(f"{len(datas)} packets")


def cmd_annotate(args) -> None:
    """Regenerate the meta sidecar from buffer hex after in-buffer edits."""
    datas = parse_hex_lines(sys.stdin)
    old_meta = read_meta(args.meta)
    linktype = (old_meta or {}).get("linktype", args.linktype)
    times, wirelens = carried_times_and_wirelens(old_meta)
    write_meta(args.meta, annotate(datas, linktype, args.limit, times, wirelens))


def cmd_ascii(args) -> None:
    """Render buffer hex as printable ASCII, aligned to the hex columns."""
    for data in parse_hex_lines(sys.stdin):
        print(printable(data, "  "))


def cmd_utf8(args) -> None:
    """Render buffer hex decoded as UTF-8 text."""
    for data in parse_hex_lines(sys.stdin):
        print(data.decode("utf-8", errors="replace"))


def cmd_summary(args) -> None:
    """Print a one-line scapy summary per packet."""
    require_scapy("summaries")
    for data in parse_hex_lines(sys.stdin):
        print(dissect(data, args.linktype, args.proto).summary())


# serve/rpc ops that dissect packets; refused with a clear error without scapy.
SCAPY_OPS = {"show", "fix", "setfield", "craft", "filter", "follow", "stats", "anon"}


def handle_request(request: dict) -> dict:
    """Dispatch one JSON request from the plugin and build its response."""
    operation = request.get("op")
    linktype = int(request.get("linktype", DEFAULT_LINKTYPE))
    limit = int(request.get("limit", 2000))

    if operation in SCAPY_OPS and not HAS_SCAPY:
        return {"error": "needs scapy (pip install scapy)"}

    def packets_in(key="packets"):
        return [bytes.fromhex(h.replace(" ", "")) for h in request.get(key, [])]

    def single():
        return bytes.fromhex(request.get("hex", "").replace(" ", ""))

    if operation == "packet":
        meta = annotate([single()], linktype, 1,
                        [str(request.get("t", "0"))],
                        [int(request.get("wl", 0))])
        return {"packet": meta["packets"][0]}
    if operation == "annotate":
        return annotate(packets_in(), linktype, limit,
                        [str(t) for t in request.get("times", [])],
                        [int(w) for w in request.get("wirelens", [])])
    if operation == "show":
        packet = dissect(single(), linktype, request.get("proto") or None)
        dump = packet.summary() + "\n" + packet.show(dump=True)
        return {"lines": dump.splitlines()}
    if operation == "fix":
        fixed = [fix_bytes(data, linktype) for data in packets_in()]
        return {"packets": [data.hex(" ") for data in fixed]}
    if operation == "setfield":
        return {"hex": set_field(single(), linktype, request.get("spec", "")).hex(" ")}
    if operation == "craft":
        result = eval(request.get("expr", ""), scapy_namespace())
        if not isinstance(result, Packet):
            raise ValueError("expression did not produce a scapy packet")
        return {"hex": raw(result).hex(" ")}
    if operation == "command":
        return {"command": dissect(single(), linktype).command()}
    if operation == "filter":
        return {"indices": filter_indices(packets_in(), linktype,
                                          request.get("expr", ""))}
    if operation == "follow":
        indices, lines = follow_stream(packets_in(), linktype,
                                       int(request.get("index", 1)))
        return {"indices": indices, "lines": lines}
    if operation == "grep":
        return {"matches": grep_payloads(packets_in(), request.get("pattern", ""))}
    if operation == "stats":
        return {"lines": capture_stats(packets_in(), linktype,
                                       [str(t) for t in request.get("times", [])])}
    if operation == "anon":
        return {"packets": [data.hex(" ") for data in anonymise(packets_in(), linktype)]}
    if operation == "ping":
        return {"ok": True}
    return {"error": f"unknown op: {operation!r}"}


def safe_handle(request: dict) -> dict:
    try:
        return handle_request(request)
    except SystemExit:  # fail() from a bad protocol name must not kill us
        return {"error": "bad request"}
    except Exception as error:
        return {"error": str(error)}


def cmd_serve(args) -> None:
    """Serve requests as JSON lines over stdin/stdout.

    Keeps scapy imported between requests so the plugin can re-dissect
    packets live while the user edits. One request per line; always answers
    with exactly one JSON line and never exits on bad input.
    """
    for line in sys.stdin:
        try:
            response = safe_handle(json.loads(line))
        except ValueError:
            response = {"error": "bad request"}
        print(json.dumps(response, separators=(",", ":")), flush=True)


def cmd_rpc(args) -> None:
    """Answer a single JSON request: the subprocess fallback for 'serve'."""
    response = safe_handle(json.loads(sys.stdin.readline() or "{}"))
    print(json.dumps(response, separators=(",", ":")))


AGENT_TOOLS = [
    ("overview", "Capture overview: file, link type, packet count and summaries.",
     {}, []),
    ("packets", "Hex bytes and annotations for a range of packets.",
     {"from": {"type": "integer"}, "to": {"type": "integer"}}, ["from"]),
    ("detail", "Full scapy dissection tree for one packet.",
     {"index": {"type": "integer"}}, ["index"]),
    ("goto", "Move the user's cursor to a packet (and byte offset); every "
     "pane follows. Returns the field under the cursor. Use this while "
     "discussing a packet so the user sees what you mean.",
     {"index": {"type": "integer"}, "byte": {"type": "integer"}}, ["index"]),
    ("set_field", "Set a protocol field by name on one packet, e.g. spec "
     "'IP.ttl=12'. Checksums and lengths are recomputed.",
     {"index": {"type": "integer"}, "spec": {"type": "string"}},
     ["index", "spec"]),
    ("fix", "Recompute checksums and length fields for a packet range.",
     {"from": {"type": "integer"}, "to": {"type": "integer"}}, []),
    ("replace", "Replace one packet's bytes with new space-separated hex.",
     {"index": {"type": "integer"}, "hex": {"type": "string"}},
     ["index", "hex"]),
    ("insert", "Insert a packet after position 'after' (0 = top), from a "
     "scapy expression like Ether()/IP()/ICMP().",
     {"after": {"type": "integer"}, "expr": {"type": "string"}}, ["expr"]),
    ("delete", "Delete one packet.",
     {"index": {"type": "integer"}}, ["index"]),
    ("filter", "Fold the view to packets matching a layer name ('DNS') or "
     "Python expression over p ('p[TCP].dport == 80').",
     {"expr": {"type": "string"}}, ["expr"]),
    ("clear_filter", "Clear the current filter/fold.", {}, []),
    ("follow", "Fold to one packet's TCP/UDP conversation and show the "
     "reassembled stream.", {"index": {"type": "integer"}}, ["index"]),
    ("grep", "Regex-search decoded payloads; returns packet/byte matches.",
     {"pattern": {"type": "string"}}, ["pattern"]),
    ("stats", "Protocol, conversation and port statistics.", {}, []),
    ("ex", "Run a raw Vim ex command (only if the user has enabled "
     "g:vimcap_agent_raw).", {"command": {"type": "string"}}, ["command"]),
]


def cmd_mcp(args) -> None:
    """MCP stdio server bridging an agent (e.g. Claude Code) to a Vim session.

    The agent's client spawns this process; Vim polls the session file for
    the port, connects, and authenticates with the token. Tool calls are
    forwarded over Vim's JSON channel protocol as calls to
    vimcap#agent#dispatch(), so the agent only reaches the operations that
    function exposes.
    """
    import os
    import secrets
    import select
    import socket

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    token = secrets.token_hex(16)
    session = Path(args.session)
    session.write_text(json.dumps(
        {"port": listener.getsockname()[1], "token": token}))
    session.chmod(0o600)

    vim, vim_authed, vim_buffer = None, False, ""
    stdin_fd, stdin_buffer = sys.stdin.fileno(), ""
    pending, next_call_id = {}, 1
    decoder = json.JSONDecoder()

    def reply(request_id, result=None, error=None):
        message = {"jsonrpc": "2.0", "id": request_id}
        message["error" if error else "result"] = error or result
        print(json.dumps(message), flush=True)

    def tool_result(request_id, payload):
        is_error = isinstance(payload, dict) and "error" in payload
        text = payload if isinstance(payload, str) else json.dumps(
            payload, indent=2, default=str)
        reply(request_id, result={
            "content": [{"type": "text", "text": text}], "isError": is_error})

    def handle_vim(message):
        nonlocal vim_authed
        if not isinstance(message, list) or len(message) != 2:
            return
        call_id, payload = message
        if isinstance(payload, dict) and "auth" in payload:
            vim_authed = payload["auth"] == token
            vim.sendall((json.dumps([call_id, "ok" if vim_authed else "bad token"])
                         + "\n").encode())
        elif call_id in pending:
            tool_result(pending.pop(call_id), payload)

    def handle_mcp(request):
        nonlocal next_call_id
        request_id, method = request.get("id"), request.get("method", "")
        params = request.get("params", {})
        if method == "initialize":
            reply(request_id, result={
                "protocolVersion": params.get("protocolVersion", "2024-11-05"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "vimcap", "version": "1.0"}})
        elif method == "tools/list":
            reply(request_id, result={"tools": [
                {"name": name, "description": description,
                 "inputSchema": {"type": "object", "properties": properties,
                                 "required": required}}
                for name, description, properties, required in AGENT_TOOLS]})
        elif method == "tools/call":
            if vim is None or not vim_authed:
                tool_result(request_id,
                            {"error": "vim has not connected to this session yet"})
                return
            call = [["call", "vimcap#agent#dispatch",
                     [params.get("name", ""), params.get("arguments", {})],
                     next_call_id]]
            pending[next_call_id] = request_id
            next_call_id += 1
            vim.sendall((json.dumps(call[0]) + "\n").encode())
        elif method == "ping":
            reply(request_id, result={})
        elif request_id is not None:
            reply(request_id, error={"code": -32601,
                                     "message": f"unknown method {method}"})

    while True:
        sources = [stdin_fd, listener] + ([vim] if vim else [])
        readable, _, _ = select.select(sources, [], [])
        if stdin_fd in readable:
            # Read at the raw fd level: a buffered readline() would strand
            # later messages in Python's buffer where select cannot see them.
            chunk = os.read(stdin_fd, 65536)
            if not chunk:
                break
            stdin_buffer += chunk.decode("utf-8", errors="replace")
            while "\n" in stdin_buffer:
                line, stdin_buffer = stdin_buffer.split("\n", 1)
                if not line.strip():
                    continue
                try:
                    handle_mcp(json.loads(line))
                except ValueError:
                    pass
        if listener in readable:
            connection, _ = listener.accept()
            if vim is None:
                vim = connection
            else:
                connection.close()
        if vim is not None and vim in readable:
            data = vim.recv(65536)
            if not data:
                # Vim went away: fail any in-flight tool calls so the agent
                # gets an error instead of hanging, and release the socket.
                for request_id in pending.values():
                    tool_result(request_id, {"error": "vim disconnected"})
                pending.clear()
                vim.close()
                vim, vim_authed, vim_buffer = None, False, ""
                continue
            vim_buffer += data.decode("utf-8", errors="replace")
            while vim_buffer.strip():
                try:
                    message, consumed = decoder.raw_decode(vim_buffer.lstrip())
                except ValueError:
                    break
                vim_buffer = vim_buffer.lstrip()[consumed:]
                handle_vim(message)
    session.unlink(missing_ok=True)


def _is_permission_error(error) -> bool:
    """scapy wraps capture-device permission failures in its own exception
    types, so recognise them by message as well as by PermissionError."""
    if isinstance(error, PermissionError):
        return True
    text = str(error).lower()
    return "permission denied" in text or "operation not permitted" in text \
        or "bpf" in text


def cmd_sniff(args) -> None:
    """Capture packets from an interface and print them as hex lines."""
    require_scapy("sniffing")
    from scapy.all import sniff

    try:
        packets = sniff(iface=args.iface or None, count=args.count,
                        timeout=args.timeout)
    except Exception as error:
        if _is_permission_error(error):
            fail("sniffing needs capture privileges (run vim with sudo, or "
                 "grant your user access to the capture device, e.g. on macOS "
                 "add yourself to the access_bpf group)")
        fail(f"sniff failed: {error}")
    for packet in packets:
        print(raw(packet).hex(" "))


def cmd_send(args) -> None:
    """Transmit buffer packets on an interface (requires privileges)."""
    require_scapy("sending")
    from scapy.all import sendp

    datas = parse_hex_lines(sys.stdin)
    packets = [dissect(data, args.linktype) for data in datas]
    try:
        sendp(packets, iface=args.iface or None, verbose=False)
    except Exception as error:
        if _is_permission_error(error):
            fail("sending needs raw-socket privileges (run vim with sudo)")
        fail(f"send failed: {error}")
    print(f"{len(packets)} packets sent")


def cmd_show(args) -> None:
    """Print scapy's full dissection tree for a single packet."""
    require_scapy("the dissection tree")
    datas = parse_hex_lines(sys.stdin)
    if not datas:
        fail("no packet under the cursor")
    packet = dissect(datas[0], args.linktype, args.proto)
    print(packet.summary())
    print(packet.show(dump=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vimcap")
    commands = parser.add_subparsers(dest="command", required=True)

    def common(sub):
        sub.add_argument("--linktype", type=int, default=DEFAULT_LINKTYPE)
        sub.add_argument("--limit", type=int, default=2000)
        return sub

    load = commands.add_parser("load")
    load.add_argument("path")
    load.add_argument("--meta", required=True)
    common(load)
    load.set_defaults(handler=cmd_load)

    save = commands.add_parser("save")
    save.add_argument("path")
    save.add_argument("--meta")
    common(save)
    save.set_defaults(handler=cmd_save)

    annotate_cmd = commands.add_parser("annotate")
    annotate_cmd.add_argument("--meta", required=True)
    common(annotate_cmd)
    annotate_cmd.set_defaults(handler=cmd_annotate)

    serve = commands.add_parser("serve")
    serve.set_defaults(handler=cmd_serve)

    rpc = commands.add_parser("rpc")
    rpc.set_defaults(handler=cmd_rpc)

    mcp = commands.add_parser("mcp")
    mcp.add_argument("--session", required=True)
    mcp.set_defaults(handler=cmd_mcp)

    sniff = commands.add_parser("sniff")
    sniff.add_argument("--iface", default="")
    sniff.add_argument("--count", type=int, default=10)
    sniff.add_argument("--timeout", type=int, default=15)
    sniff.set_defaults(handler=cmd_sniff)

    send = common(commands.add_parser("send"))
    send.add_argument("--iface", default="")
    send.set_defaults(handler=cmd_send)

    for name, handler in (
        ("ascii", cmd_ascii),
        ("utf8", cmd_utf8),
        ("summary", cmd_summary),
        ("show", cmd_show),
    ):
        sub = common(commands.add_parser(name))
        sub.add_argument("--proto")
        sub.set_defaults(handler=handler)

    return parser


if __name__ == "__main__":
    arguments = build_parser().parse_args()
    arguments.handler(arguments)
