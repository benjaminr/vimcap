vimcap 🧢
=========

Vim as a hex editor for packet captures.

<img width="1200" height="660" alt="vimcap" src="https://github.com/user-attachments/assets/cc128430-745d-4d6f-891c-cd99ec33d505" />

Open a `.pcap` (or `.pcapng`) and every packet becomes a line of hex you can
edit like any other text — except vimcap knows what the bytes *mean*:

- **Layer colouring** — each protocol layer's bytes (Ethernet / IP / TCP /
  payload) are highlighted in a different colour.
- **Field inspector** — the statusline names the exact field under the
  cursor as you move: `pkt 3/120  byte 0x16  IP.ttl = 64`.
- **Fields are words** — `w` and `b` jump between protocol fields; `h` and
  `l` move a byte at a time.
- **Themed, coordinated panes** — opening a capture lays out the workspace:
  a rich dissection pane on the right (styled header, protocol path, per-field
  byte offsets, bad-checksum flags, with the cursor's field highlighted — `K`
  toggles it) and ASCII/binary views underneath. One theme drives every pane
  (`mono`/`neon`/`warm`/`classic` or your own), every pane tracks the cursor,
  and the mouse can scroll any of them. The cursor links **both ways** — move
  in a pane and the hex view (and the others) follow to the same byte/packet.
  `<Tab>` cycles zoom: maximise-keeping-the-sidebar → fullscreen → restore.
- **Live re-dissection** — edit a byte and the colours, field names,
  summaries and open panes update themselves moments later, served by a
  persistent scapy process (sub-millisecond per packet once warm).
- **Faithful saves** — `:w` writes a valid capture preserving the link type
  and per-packet timestamps; saving an unedited buffer is byte-identical to
  the original.

Ordinary Vim editing does the rest: `r` rewrites a nibble, `R` overtypes a
run of bytes, `dd` drops a packet, `yy`/`p` replays one.

New to it? Opening a capture shows a welcome splash with the logo and a command
cheatsheet (`:VimcapHelp` or `>?` toggles it; `g:vimcap_welcome = 0` to opt out).

And because scapy is already warm in the helper daemon, the whole toolbox
comes along:

- **Checksums** — broken IP/TCP/UDP checksums show a `✗` in the statusline;
  `:VimcapFix` recomputes them (and length fields).
- **Field editing** — `>f` or `:VimcapSet ttl=12` writes a field by name,
  fixing checksums around it. `:VimcapNew Ether()/IP()/ICMP()` crafts and
  appends a packet; `:VimcapCommand` yanks the scapy expression that
  rebuilds the current one.
- **Filtering** — `:VimcapFilter DNS` or `:VimcapFilter p[TCP].dport == 80`
  folds away everything else; `:VimcapFollow` folds to the conversation
  under the cursor and shows the reassembled stream.
- **Search & stats** — `:VimcapGrep pattern` loads payload matches into the
  quickfix list; `:VimcapStats` charts protocols, conversations and ports as
  bars.
- **Captures in, captures out** — `:VimcapSniff en0` streams live traffic
  into the buffer packet-by-packet as it's captured (`:VimcapSniffStop` to end
  early; needs capture privileges; open an empty `vim live.pcap` and the first
  packets lay out your whole workspace); `:VimcapSend` replays packets (off unless
  `g:vimcap_allow_send = 1`); `:VimcapDiff other.pcap` compares captures
  vimdiff-style; `:VimcapAnon` rewrites MACs/IPs consistently for sharing.
- **Agentic mode** — run `:VimcapAgent why does packet 12 look corrupt?` (or
  bare `:VimcapAgent`) to open Claude Code alongside the capture, connected
  over a local MCP bridge with structured pcap tools: it reads dissections,
  moves your cursor (every pane follows), fixes checksums, filters and edits
  packets while you watch — and you chat with it in the terminal as usual.
  Opt in per session, or set `g:vimcap_auto_agent = 1` to open it on every
  capture. Scoped to capture operations; raw ex commands stay off unless you
  opt in.


Dependencies
------------

- Vim 8.2+ (with `+textprop`) or Neovim
- Python 3.7+ (standard library only — this is all the hex editor needs)
- [Scapy](https://scapy.net/) **(optional)** — unlocks dissection: colours,
  the field inspector, and the filter/follow/stats/craft toolbox

Vim does not need `+python3`; the helper runs as an external command. Without
scapy you still get a fully working hex editor with byte-faithful saves — just
no dissection. `:VimcapHealth` reports what was found.


Installation
------------

With a plugin manager, add a build hook so scapy is provisioned automatically:

```vim
" vim-plug
Plug 'benjaminr/vimcap', { 'do': './install.sh' }
```
```lua
-- lazy.nvim
{ 'benjaminr/vimcap', build = './install.sh' }
```

Or native packages:

```bash
mkdir -p ~/.vim/pack/vendor/start/ && cd $_
git clone https://github.com/benjaminr/vimcap
cd vimcap && ./install.sh        # creates .venv with scapy + help tags
```

`install.sh` uses [uv](https://docs.astral.sh/uv/) when present, else
`python3 -m venv`, and the plugin picks the resulting `.venv` up automatically
— no `g:vimcap_python` needed. (Prefer your own interpreter? Point the plugin
at it: `let g:vimcap_python = '/path/to/python'`, or skip scapy entirely for
just the hex editor.)


Usage
-----

```bash
vim capture.pcap
```

| Key / command        | Action                                              |
|----------------------|-----------------------------------------------------|
| `K`                  | Toggle the dissection pane (follows the cursor)     |
| `w` / `b`            | Next / previous protocol field                      |
| `h` / `l`            | Previous / next byte                                |
| `>a` / `:VimcapAscii`| ASCII pane below the hex, column-aligned            |
| `>b` / `:VimcapBits` | Binary pane: `█·█·█·█·` per byte, coloured bits     |
| `>s` / `:VimcapSummary` | One-line scapy summary per packet, scroll-bound  |
| `>u` / `:VimcapUtf8` | Packets decoded as UTF-8, below the hex             |
| `<Tab>` / `:VimcapZoom` | Zoom cycle: focus+sidebar → fullscreen → restore |
| `Q` / `>q` / `:VimcapClose`| Close all panes (`q` from inside a pane too)  |
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
let g:vimcap_live = 1                  " re-dissect automatically while editing
let g:vimcap_live_delay = 300          " debounce (ms) before re-dissection
let g:vimcap_mouse = 1                 " enable the mouse if not configured
```

**Layout** — panes open in two regions: a full-height column on the right
and a stack under the hex. The order, region and size are all yours:

```vim
" which panes open, and in what order (detail/ascii/bits/utf8/summary/stats)
let g:vimcap_panes = ['detail', 'ascii', 'bits']
" move individual panes between regions ('right' column / 'bottom' stack)
let g:vimcap_pane_region = {'bits': 'right'}
let g:vimcap_pane_width = 64            " right column width (columns)
let g:vimcap_pane_height = 10           " bottom pane height (lines)
let g:vimcap_pane_size = {'detail': 25} " per-pane cross-size override
" agent terminal placement
let g:vimcap_agent_position = 'right'   " 'right' | 'left' | 'bottom'
let g:vimcap_agent_width = 80
```

**Theme** — one palette drives every pane, so the colours read as a set (an
IP layer is the same colour in the hex, the detail heading and the summary):

```vim
let g:vimcap_theme = 'mono'   " mono | neon | warm | classic (follows your colourscheme)
```

Or switch live with `:VimcapTheme neon` (tab-completes the names).

Define your own in `g:vimcap_themes`, or override individual groups
(`VimcapLayer0`–`3`, `VimcapPayload`, `VimcapCursorByte`, `VimcapHeader`,
`VimcapOffset`, `VimcapBar`, …) — see `:help vimcap-highlighting`.


Limitations
-----------

- pcapng files are read transparently but saved in classic pcap format.
- Nanosecond timestamps are rounded to microseconds on save.
- Inserting/deleting packets mid-capture keeps exact timestamps only up to the
  first changed packet; later ones are carried forward best-effort.
- Editing a packet makes its length authoritative, so a wire-truncated packet
  loses its original wire length when re-saved after an edit.
- Very large captures are better trimmed first (`tcpdump -r big.pcap -c 5000 -w small.pcap`).


Testing
-------

```bash
VIMCAP_PYTHON=/path/to/python-with-scapy test/run.sh
```

The suite drives a headless Vim through loading, inspecting, editing and
saving a generated capture, and verifies byte-level round-trip fidelity.
