vimcap 🧢
=========

Vim as a hex editor for packet captures.

Open a `.pcap` (or `.pcapng`) and every packet becomes a line of hex you can
edit like any other text — except vimcap knows what the bytes *mean*:

- **Layer colouring** — each protocol layer's bytes (Ethernet / IP / TCP /
  payload) are highlighted in a different colour.
- **Field inspector** — the statusline names the exact field under the
  cursor as you move: `pkt 3/120  byte 0x16  IP.ttl = 64`.
- **Fields are words** — `w` and `b` jump between protocol fields; `h` and
  `l` move a byte at a time.
- **`K` to dissect** — the full scapy dissection tree for the packet under
  the cursor, in a split.
- **Faithful saves** — `:w` writes a valid capture preserving the link type
  and per-packet timestamps; saving an unedited buffer is byte-identical to
  the original.

Ordinary Vim editing does the rest: `r` rewrites a nibble, `R` overtypes a
run of bytes, `dd` drops a packet, `yy`/`p` replays one.


Dependencies
------------

- Vim 8.2+ (with `+textprop`) or Neovim
- Python 3.9+ with [Scapy](https://scapy.net/): `pip install scapy`

Vim does not need `+python3`; the helper runs as an external command. If
scapy lives in a virtualenv, point the plugin at it:

```vim
let g:vimcap_python = expand('~/.virtualenvs/scapy/bin/python')
```


Installation
------------

Native packages:

```bash
mkdir -p ~/.vim/pack/vendor/start/
cd $_
git clone https://github.com/benjaminr/vimcap
vim -u NONE -c "helptags vimcap/doc" -c q
```

Or with any plugin manager, e.g. vim-plug: `Plug 'benjaminr/vimcap'`.


Usage
-----

```bash
vim capture.pcap
```

| Key / command        | Action                                              |
|----------------------|-----------------------------------------------------|
| `K`                  | Dissection tree for the packet under the cursor     |
| `w` / `b`            | Next / previous protocol field                      |
| `h` / `l`            | Previous / next byte                                |
| `>a` / `:VimcapAscii`| ASCII pane, column-aligned and cursor-bound         |
| `>s` / `:VimcapSummary` | One-line scapy summary per packet, scroll-bound  |
| `>u` / `:VimcapUtf8` | Packets decoded as UTF-8                            |
| `K` (visual)         | Interpret selected bytes (hex, ASCII, BE/LE ints)   |
| `:VimcapGoto 0x14`   | Jump to a byte offset within the packet             |
| `:VimcapRefresh`     | Re-dissect after editing (also happens on save)     |
| `:w`                 | Write the capture back, timestamps intact           |

`:VimcapSummary IP` or `:VimcapDetail IP` force dissection to start at a
given scapy protocol instead of the capture's link type.

Full documentation: `:help vimcap`.


Configuration
-------------

```vim
let g:vimcap_python = 'python3'        " interpreter with scapy installed
let g:vimcap_byte_motions = 1          " h/l bytes, w/b fields
let g:vimcap_statusline = 1            " packet/byte/field statusline
let g:vimcap_highlight = 1             " per-layer colouring
let g:vimcap_annotate_limit = 2000     " packets to dissect for annotations
```

Layer colours are ordinary highlight groups (`VimcapLayer0`–`VimcapLayer3`,
`VimcapPayload`, `VimcapCursorByte`) — link them to whatever suits your
colourscheme.


Limitations
-----------

- pcapng files are read transparently but saved in classic pcap format.
- Nanosecond timestamps are rounded to microseconds on save.
- Very large captures are better trimmed first (`tcpdump -r big.pcap -c 5000 -w small.pcap`).


Testing
-------

```bash
VIMCAP_PYTHON=/path/to/python-with-scapy test/run.sh
```

The suite drives a headless Vim through loading, inspecting, editing and
saving a generated capture, and verifies byte-level round-trip fidelity.
