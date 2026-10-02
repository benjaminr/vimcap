#!/usr/bin/env python3
"""Helper script for vimcap: converts packet captures to and from editable hex.

Invoked by the Vim plugin, never directly by users. Each subcommand reads
hex lines on stdin and/or a capture file, and communicates annotations
(timestamps, link type, per-field byte offsets) through a JSON "meta" file
so that saving a buffer round-trips the original capture faithfully.
"""

import argparse
import json
import logging
import sys
from decimal import Decimal
from pathlib import Path

def fail_early(message: str) -> None:
    print(f"vimcap: {message}", file=sys.stderr)
    sys.exit(1)


# Keep scapy's chatter out of stderr: the plugin treats stderr as warnings.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

try:
    import scapy.all  # noqa: F401  (registers every protocol layer)
    from scapy.compat import raw
    from scapy.config import conf
    from scapy.packet import NoPayload, Packet, Raw
    from scapy.utils import PcapReader, RawPcapWriter
except ImportError:
    fail_early(
        "scapy is required (pip install scapy); "
        "set g:vimcap_python to an interpreter that has it"
    )

MAX_FIELD_VALUE_LEN = 48
DEFAULT_LINKTYPE = 1  # DLT_EN10MB (Ethernet)
PAYLOAD_LAYERS = {"Raw", "Padding"}


def fail(message: str) -> None:
    """Report a fatal error to the plugin and exit non-zero."""
    print(f"vimcap: {message}", file=sys.stderr)
    sys.exit(1)


def warn(message: str) -> None:
    """Report a non-fatal warning; the plugin echoes lines mentioning vimcap."""
    print(f"vimcap: {message}", file=sys.stderr)


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


def layer_and_field_ranges(packet: Packet):
    """Compute absolute byte ranges for every layer and field of a packet.

    Returns (layers, fields) where each layer is [start, end, name] and each
    field is [start, end, layer_name, field_name, value]. Field offsets are
    recovered by replaying each layer's field parsers over its own bytes,
    which also handles bit-packed fields sharing a byte.
    """
    layers = []
    fields = []
    current, base = packet, 0
    while isinstance(current, Packet) and not isinstance(current, NoPayload):
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
            fields.append(
                [base + start_byte, base + end_byte, current.name, field.name, value]
            )
        base += header_len
        current = current.payload
    return layers, fields


def annotate(datas, linktype, limit, times, wirelens):
    """Build the meta structure for a list of packet byte strings."""
    entries = []
    for index, data in enumerate(datas):
        entry = {
            "t": times[index] if index < len(times) else (times[-1] if times else "0"),
            "wl": wirelens[index]
            if index < len(wirelens) and len(data) <= wirelens[index]
            else len(data),
        }
        if index < limit:
            packet = dissect(data, linktype)
            try:
                entry["s"] = packet.summary()
                entry["layers"], entry["fields"] = layer_and_field_ranges(packet)
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
    packets = []
    try:
        with PcapReader(args.path) as reader:
            packets = list(reader)
        linktype = getattr(reader, "linktype", None)
    except Exception as error:
        fail(f"could not read {args.path}: {error}")
    if linktype is None:
        # pcapng stores link types per interface; recover it from the first
        # dissected packet's class, defaulting to Ethernet.
        first_cls = packets[0].__class__ if packets else None
        linktype = conf.l2types.layer2num.get(first_cls, DEFAULT_LINKTYPE)

    datas = [raw(p) for p in packets]
    times = [str(p.time) for p in packets]
    wirelens = [getattr(p, "wirelen", None) or len(d) for p, d in zip(packets, datas)]

    meta = annotate(datas, linktype, args.limit, times, wirelens)
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
        writer = RawPcapWriter(temp_path, linktype=linktype, sync=True)
        writer.write_header(None)
        for index, data in enumerate(datas):
            stamp = Decimal(times[index] if index < len(times) else (times[-1] if times else "0"))
            seconds = int(stamp)
            microseconds = int((stamp - seconds) * 1_000_000)
            wirelen = (
                wirelens[index]
                if index < len(wirelens) and len(data) <= wirelens[index]
                else len(data)
            )
            writer.write_packet(data, sec=seconds, usec=microseconds, wirelen=wirelen)
        writer.close()
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
        print("  ".join(chr(b) if 32 <= b < 127 else "." for b in data))


def cmd_utf8(args) -> None:
    """Render buffer hex decoded as UTF-8 text."""
    for data in parse_hex_lines(sys.stdin):
        print(data.decode("utf-8", errors="replace"))


def cmd_summary(args) -> None:
    """Print a one-line scapy summary per packet."""
    for data in parse_hex_lines(sys.stdin):
        print(dissect(data, args.linktype, args.proto).summary())


def cmd_show(args) -> None:
    """Print scapy's full dissection tree for a single packet."""
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
