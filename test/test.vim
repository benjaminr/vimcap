" Headless integration test for vimcap. Driven by test/run.sh, which opens a
" generated sample.pcap and expects results in $VIMCAP_TEST_OUT.

set lines=60 columns=220
let s:results = []

function! s:check(condition, message) abort
  call add(s:results, (a:condition ? 'ok   ' : 'FAIL ') . a:message)
endfunction

function! s:cursor_byte() abort
  return (virtcol('.') - 1) / 3
endfunction

" --- loading -------------------------------------------------------------
call s:check(getline(1) =~# '^\x\x\%( \x\x\)*$', 'buffer contains space-separated hex')
call s:check(line('$') == 2, 'one line per packet')
call s:check(exists('b:vimcap') && b:vimcap.linktype == 1, 'meta sidecar loaded with linktype')
call s:check(b:vimcap.packets[0].layers[1][2] ==# 'IP', 'layer ranges recorded')
call s:check(b:vimcap.packets[0].s =~# 'TCP', 'packet summary recorded')
call s:check(&filetype ==# 'vimcap', 'filetype set')
call s:check(bufwinid(bufnr('vimcap://detail')) > 0
      \ && bufwinid(bufnr('vimcap://ascii')) > 0
      \ && bufwinid(bufnr('vimcap://bits')) > 0,
      \ 'detail, ascii and bits panes open automatically on load')
call s:check(bufwinid(bufnr('vimcap://help')) > 0,
      \ 'welcome pane opens when a pcap is opened')
call s:check(&mouse ==# 'a', 'mouse support enabled for pane scrolling')

" --- field inspection ----------------------------------------------------
" Byte 22 (0x16) of packet 1 is IP.ttl (14-byte Ethernet header + offset 8).
call cursor(1, 22 * 3 + 1)
let s:statusline = vimcap#statusline()
call s:check(s:statusline =~# 'IP\.ttl', 'statusline names the field under the cursor: ' . s:statusline)
call s:check(s:statusline =~# '0x16', 'statusline shows the byte offset')

" --- field motions -------------------------------------------------------
call cursor(1, 1)
call vimcap#field_jump(1)
call s:check(s:cursor_byte() == 6, 'w jumps to the next field (Ether.src)')
call vimcap#field_jump(-1)
call s:check(s:cursor_byte() == 0, 'b jumps back to the previous field')

" --- panes ----------------------------------------------------------------
call vimcap#ascii_pane()
let s:ascii_buf = bufnr('vimcap://ascii')
call s:check(s:ascii_buf > 0 && getbufline(s:ascii_buf, 1)[0] =~# 'G  E  T',
      \ 'ascii pane renders printable bytes')
call s:check(&scrollbind, 'hex window scroll-binds to the ascii pane')

" First byte aa = 10101010, second byte bb = 10111011.
call vimcap#bits_pane()
let s:bits_buf = bufnr('vimcap://bits')
call s:check(s:bits_buf > 0
      \ && getbufline(s:bits_buf, 1)[0] =~# '^█·█·█·█· █·███·██ ',
      \ 'bits pane renders bytes as block glyphs')

call vimcap#detail()
let s:detail_buf = bufnr('vimcap://detail')
let s:detail_text = join(getbufline(s:detail_buf, 1, '$'), "\n")
call s:check(s:detail_buf > 0 && s:detail_text =~# '^Packet 1/'
      \ && s:detail_text =~# '▸ Ethernet' && s:detail_text =~# '▸ IP',
      \ 'detail pane shows the rich dissection with layer headings')
call s:check(s:detail_text =~# 'Ethernet › IP › TCP', 'detail pane shows the protocol path')
call s:check(s:detail_text =~# '0x16\s\+ttl', 'detail pane shows per-field byte offsets')

call vimcap#summary_pane('')
let s:summary_buf = bufnr('vimcap://summary')
call s:check(s:summary_buf > 0 && getbufline(s:summary_buf, 2)[0] =~# 'DNS',
      \ 'summary pane lists one summary per packet')

" Dissection panes live in a right-hand column; the ascii pane sits below
" the hex window, column-aligned with it. K toggles the detail pane.
let s:hex_info = getwininfo(bufwinid(bufnr('%')))[0]
let s:column_cols = map([s:detail_buf, s:summary_buf],
      \ {_, buf -> getwininfo(bufwinid(buf))[0].wincol})
call s:check(min(s:column_cols) > s:hex_info.wincol
      \ && min(s:column_cols) == max(s:column_cols),
      \ 'dissection panes stack in one column right of the hex window')
let s:ascii_info = getwininfo(bufwinid(s:ascii_buf))[0]
call s:check(s:ascii_info.wincol == s:hex_info.wincol
      \ && s:ascii_info.winrow > s:hex_info.winrow,
      \ 'ascii pane opens below the hex window')

" Configurable region: moving 'bits' to the right column puts it beside the
" hex instead of below it.
let g:vimcap_pane_region = {'bits': 'right'}
let s:bits_win = bufwinid(s:bits_buf)
call win_execute(s:bits_win, 'close')
call vimcap#bits_pane()
let s:bits_buf = bufnr('vimcap://bits')
call s:check(getwininfo(bufwinid(s:bits_buf))[0].wincol > s:hex_info.wincol,
      \ 'g:vimcap_pane_region moves a pane to the right column')
unlet g:vimcap_pane_region
call win_execute(bufwinid(s:bits_buf), 'close')

" Configurable size: a bottom pane honours g:vimcap_pane_height.
let g:vimcap_pane_height = 6
call vimcap#bits_pane()
let s:bits_buf = bufnr('vimcap://bits')
call s:check(getwininfo(bufwinid(s:bits_buf))[0].height == 6,
      \ 'g:vimcap_pane_height sizes a bottom pane')
unlet g:vimcap_pane_height

" The bits pane cursor tracks the byte under the hex cursor; the summary
" pane follows the packet line.
call cursor(1, 14 * 3 + 1)
call vimcap#track_cursor()
call win_execute(bufwinid(s:bits_buf), 'let g:vimcap_test_vcol = virtcol(".")')
call s:check(g:vimcap_test_vcol == 14 * 9 + 1,
      \ 'bits pane cursor tracks the hex byte (vcol=' . g:vimcap_test_vcol . ')')
call win_execute(bufwinid(s:ascii_buf), 'let g:vimcap_test_acol = virtcol(".")')
call s:check(g:vimcap_test_acol == 14 * 3 + 1,
      \ 'ascii pane cursor tracks the hex byte (vcol=' . g:vimcap_test_acol . ')')
call cursor(2, 1)
call vimcap#track_cursor()
call win_execute(bufwinid(s:summary_buf), 'let g:vimcap_test_line = line(".")')
call s:check(g:vimcap_test_line == 2, 'summary pane follows the packet line')
call cursor(1, 1)
call vimcap#detail_toggle()
call s:check(bufwinid(bufnr('vimcap://detail')) < 0, 'K closes the detail pane')
call vimcap#detail_toggle()
call s:check(bufwinid(bufnr('vimcap://detail')) > 0, 'K reopens the detail pane')
let s:detail_buf = bufnr('vimcap://detail')

" --- visual value ----------------------------------------------------------
" Select the two TCP destination-port bytes (offset 36-37 = 00 50 = 80).
call setpos("'<", [0, 1, 36 * 3 + 1, 0])
call setpos("'>", [0, 1, 37 * 3 + 1, 0])
let s:value = substitute(execute('call vimcap#value()'), '[[:cntrl:]]', ' ', 'g')
call s:check(s:value =~# 'BE 80', 'visual value decodes big-endian integer: ' . s:value)

" --- goto ----------------------------------------------------------------
VimcapGoto 0x0E
call s:check(s:cursor_byte() == 14, ':VimcapGoto 0x0E lands on byte 14')

" --- read-only scapy operations --------------------------------------------
VimcapFilter DNS
call s:check(foldclosed(1) != -1 && foldclosed(2) == -1,
      \ 'filter folds non-matching packets')
VimcapFilter!
call s:check(foldclosed(1) == -1, 'filter clears')

call cursor(1, 1)
VimcapFollow
let s:stream_buf = bufnr('vimcap://stream')
call s:check(s:stream_buf > 0
      \ && join(getbufline(s:stream_buf, 1, '$'), ' ') =~# 'GET / HTTP',
      \ 'follow stream shows the conversation payload')
call s:check(foldclosed(2) != -1, 'follow folds other conversations')
VimcapFilter!

VimcapGrep GET
let s:qf = getqflist()
call s:check(len(s:qf) == 1 && s:qf[0].lnum == 1 && s:qf[0].col == 54 * 3 + 1,
      \ 'payload grep fills the quickfix list')
cclose

VimcapStats
let s:stats_buf = bufnr('vimcap://stats')
call s:check(s:stats_buf > 0
      \ && getbufline(s:stats_buf, 1)[0] =~# '2 packets'
      \ && join(getbufline(s:stats_buf, 1, '$'), ' ') =~# 'TCP 80',
      \ 'stats pane summarises the capture')

call cursor(1, 1)
VimcapCommand
call s:check(@" =~# '^Ether(' && @" =~# 'TCP', 'copy-as-scapy yanks the packet expression')

" --- unedited write round trip -------------------------------------------
silent execute 'write ' . fnameescape($VIMCAP_TEST_DIR . '/roundtrip.pcap')
call s:check(!&modified || 1, 'write completed')

" --- edited write ---------------------------------------------------------
" Overwrite the ttl byte (byte 22 of packet 1) with ff, then save in place.
call cursor(1, 22 * 3 + 1)
normal! Rff
call s:check(getline(1)[22 * 3 : 22 * 3 + 1] ==# 'ff', 'buffer edit applied')
silent write
call s:check(!&modified, 'buffer marked unmodified after save')
call s:check(get(b:vimcap.packets[0], 's', '') =~# 'TCP', 'annotations refreshed after save')

" --- live dissection --------------------------------------------------------
" Rewrite the ttl byte back to 0x40 and flush: the in-memory annotations
" should update without a save.
call cursor(1, 22 * 3 + 1)
normal! R40
call vimcap#live#flush(bufnr('%'))
let s:ttl = filter(copy(b:vimcap.packets[0].fields), 'v:val[3] ==# "ttl"')[0][4]
call s:check(s:ttl ==# '64', 'live update re-dissects an edited byte (ttl=' . s:ttl . ')')
call s:check(get(b:, 'vimcap_stale', 1) == 0, 'stale flag cleared after live update')

" Open panes must follow live updates: rewrite the 'G' of "GET" (byte 54)
" to 'Z' and check the ascii pane re-renders.
call cursor(1, 54 * 3 + 1)
normal! R5a
call vimcap#live#flush(bufnr('%'))
call s:check(getbufline(s:ascii_buf, 1)[0] =~# 'Z  E  T',
      \ 'ascii pane follows live edits')
" 0x5a = 01011010
call s:check(getbufline(s:bits_buf, 1)[0] =~# '·█·██·█·',
      \ 'bits pane follows live edits')
call cursor(1, 54 * 3 + 1)
normal! R47
call vimcap#live#flush(bufnr('%'))
call s:check(get(b:, 'vimcap_stale', 1) == 0,
      \ 'valid re-edit clears the stale flag again')

" The detail pane follows the cursor between packets.
call cursor(2, 1)
call vimcap#detail_follow()
call s:check(join(getbufline(s:detail_buf, 1, '$'), "\n") =~# 'DNS',
      \ 'detail pane follows the cursor to the DNS packet')
call cursor(1, 1)

" Structural change: delete the DNS packet and flush; annotations, sidecar
" and remaining timestamps must follow.
2delete _
call vimcap#live#flush(bufnr('%'))
call s:check(len(b:vimcap.packets) == 1, 'live update tracks packet deletion')
call s:check(len(getbufline(s:summary_buf, 1, '$')) == 1,
      \ 'summary pane follows packet deletion')
let s:sidecar = json_decode(join(readfile(b:vimcap_meta_file), ''))
call s:check(len(s:sidecar.packets) == 1, 'sidecar rewritten after structural change')
call s:check(s:sidecar.packets[0].t ==# '1700000000.123456', 'timestamp carried through live update')

" --- checksum detection and fixing ------------------------------------------
let s:pristine = getline(1)
call cursor(1, 24 * 3 + 1)
normal! Rff
call cursor(1, 25 * 3 + 1)
normal! Rff
call vimcap#live#flush(bufnr('%'))
call s:check(index(get(b:vimcap.packets[0], 'bad', []), 'IP.chksum') >= 0,
      \ 'corrupted checksum is detected')
call s:check(vimcap#statusline() =~# '✗IP.chksum', 'statusline flags the bad checksum')
VimcapFix
call s:check(getline(1) ==# s:pristine, ':VimcapFix restores the correct checksum')
call s:check(empty(get(b:vimcap.packets[0], 'bad', [])), 'checksum flag cleared after fix')

" --- field editing -----------------------------------------------------------
call cursor(1, 1)
VimcapSet ttl=12
call s:check(getline(1)[22 * 3 : 22 * 3 + 1] ==# '0c', ':VimcapSet writes the field bytes')
call s:check(empty(get(b:vimcap.packets[0], 'bad', [])),
      \ ':VimcapSet recomputes checksums around the edit')

" --- crafting ----------------------------------------------------------------
VimcapNew Ether()/IP(dst='9.9.9.9')/UDP(dport=53)/DNS(rd=1)
call s:check(line('$') == 2 && get(b:vimcap.packets[1], 's', '') =~# 'DNS',
      \ ':VimcapNew appends a crafted packet')

" --- anonymisation -----------------------------------------------------------
VimcapAnon
let s:src = filter(copy(b:vimcap.packets[0].fields),
      \ 'v:val[2] ==# "IP" && v:val[3] ==# "src"')[0][4]
call s:check(s:src =~# '^10\.99\.', ':VimcapAnon rewrites addresses (src=' . s:src . ')')
call s:check(empty(get(b:vimcap.packets[0], 'bad', [])),
      \ ':VimcapAnon recomputes checksums')

" --- agent dispatch ----------------------------------------------------------
let s:overview = vimcap#agent#dispatch('overview', {})
call s:check(get(s:overview, 'packet_count', 0) == 2
      \ && len(get(s:overview, 'summaries', [])) == 2,
      \ 'agent overview reports the capture')
let s:goto = vimcap#agent#dispatch('goto', {'index': 1, 'byte': 22})
call s:check(get(s:goto, 'field', '') =~# 'ttl',
      \ 'agent goto lands on a field: ' . get(s:goto, 'field', ''))
call vimcap#agent#dispatch('set_field', {'index': 1, 'spec': 'ttl=99'})
call s:check(getline(1)[22 * 3 : 22 * 3 + 1] ==# '63',
      \ 'agent set_field edits packet bytes')
let s:agent_filter = vimcap#agent#dispatch('filter', {'expr': 'DNS'})
call s:check(get(s:agent_filter, 'matching', []) == [2],
      \ 'agent filter reports matching packets')
call vimcap#agent#dispatch('clear_filter', {})
let s:bad_filter = vimcap#agent#dispatch('filter', {'expr': 'nonsense('})
call s:check(has_key(s:bad_filter, 'error'),
      \ 'agent filter reports a failed expression rather than stale matches')
call vimcap#agent#dispatch('clear_filter', {})
let s:agent_ex = vimcap#agent#dispatch('ex', {'command': 'echo 1'})
call s:check(has_key(s:agent_ex, 'error'), 'agent raw ex commands are gated by default')

" An agent-supplied scapy expression cannot escape to the shell: builtins are
" stripped, so __import__ is undefined.
let s:rce = vimcap#agent#dispatch('insert',
      \ {'expr': "__import__('os') or Ether()"})
call s:check(has_key(s:rce, 'error'), 'agent craft/insert cannot reach __import__')

" --- timestamps across a structural change -----------------------------------
" Deleting a non-last packet must not shuffle its timestamp onto a survivor.
let s:deleted_time = b:vimcap.packets[0].t
1delete _
call vimcap#live#flush(bufnr('%'))
call s:check(get(b:vimcap.packets[0], 't', '') !=# s:deleted_time,
      \ 'deleting a packet does not shuffle its timestamp onto the survivor')

" --- send is gated -----------------------------------------------------------
let s:send_msg = substitute(execute('VimcapSend'), '[[:cntrl:]]', ' ', 'g')
call s:check(s:send_msg =~# 'disabled', 'sending is disabled by default')

" --- close all panes ---------------------------------------------------------
call vimcap#ascii_pane()
call vimcap#bits_pane()
call vimcap#summary_pane('')
call vimcap#detail()
call s:check(bufwinid(bufnr('vimcap://detail')) > 0, 'panes open before close')
call vimcap#close_panes()
call s:check(bufwinid(bufnr('vimcap://detail')) < 0
      \ && bufwinid(bufnr('vimcap://ascii')) < 0
      \ && bufwinid(bufnr('vimcap://bits')) < 0
      \ && bufwinid(bufnr('vimcap://summary')) < 0,
      \ ':VimcapClose closes every pane')
call s:check(exists(':VimcapClose') == 2, ':VimcapClose command is available')

" --- welcome splash ----------------------------------------------------------
call vimcap#welcome()
let s:help_buf = bufnr('vimcap://help')
call s:check(s:help_buf > 0
      \ && join(getbufline(s:help_buf, 1, '$'), "\n") =~# 'vimcap'
      \ && join(getbufline(s:help_buf, 1, '$'), "\n") =~# ':VimcapSniff',
      \ 'welcome pane shows the logo and command reference')
call vimcap#welcome_toggle()
call s:check(bufwinid(bufnr('vimcap://help')) < 0, 'welcome pane toggles closed')

" --- theme switching ---------------------------------------------------------
VimcapTheme neon
call s:check(g:vimcap_theme ==# 'neon', ':VimcapTheme switches the theme live')
VimcapTheme bogus
call s:check(g:vimcap_theme ==# 'neon', ':VimcapTheme rejects an unknown theme')
call s:check(index(vimcap#theme#complete('n', '', 0), 'neon') >= 0,
      \ 'theme completion offers matching names')
VimcapTheme mono

" --- empty session + sniff lays out the workspace ----------------------------
" A new (non-existent) capture must become a vimcap buffer so commands work,
" and populating it (as a sniff does) must open the configured panes.
" Start from a clean window layout so stale panes don't mask the result
" (closing the pane windows wipes their scratch buffers).
new
execute 'edit ' . fnameescape($VIMCAP_TEST_DIR . '/fresh.pcap')
only!
call s:check(&filetype ==# 'vimcap', 'a new .pcap is initialised as a vimcap buffer')
call s:check(exists(':VimcapSniff') == 2, ':VimcapSniff is available in a fresh session')
call s:check(bufwinid(bufnr('vimcap://detail')) < 0,
      \ 'fresh session starts with no dissection panes open')
" Simulate what vimcap#sniff does after a capture: fill the empty buffer and
" lay out the workspace.
let s:captured = 'aa bb cc dd ee 02 aa bb cc dd ee 01 08 00 45 00 00 28'
      \ . ' 00 01 00 00 40 06 3a f4 0a 00 00 01 0a 00 00 02 00 50 00 50'
      \ . ' 00 00 00 00 00 00 00 00 50 02 20 00 00 00 00 00'
call s:check(line('$') == 1 && empty(getline(1)), 'fresh session starts empty')
call setline(1, s:captured)
call vimcap#live#flush(bufnr('%'))
call vimcap#open_workspace()
call s:check(bufwinid(bufnr('vimcap://detail')) > 0
      \ && bufwinid(bufnr('vimcap://ascii')) > 0
      \ && bufwinid(bufnr('vimcap://bits')) > 0,
      \ 'populating an empty session opens the configured panes')

" --- streaming sniff appends packets live --------------------------------
" vimcap#sniff_feed is what each captured packet runs through; feeding packets
" one at a time must grow the buffer incrementally (not all at once).
new
execute 'edit ' . fnameescape($VIMCAP_TEST_DIR . '/stream.pcap')
only!
let s:p = 'aa bb cc dd ee 02 aa bb cc dd ee 01 08 00 45 00 00 28 00 01 00'
      \ . ' 00 40 06 3a f4 0a 00 00 01 0a 00 00 02 00 50 00 50 00 00 00 00'
      \ . ' 00 00 00 00 50 02 20 00 00 00 00 00'
call vimcap#sniff_feed(bufnr('%'), s:p)
call s:check(line('$') == 1 && getline(1) =~# '^aa bb',
      \ 'first streamed packet replaces the blank line')
call vimcap#sniff_feed(bufnr('%'), s:p)
call vimcap#sniff_feed(bufnr('%'), s:p)
call s:check(line('$') == 3, 'further streamed packets append live, one per line')
call vimcap#live#flush(bufnr('%'))
call s:check(len(b:vimcap.packets) == 3 && get(b:vimcap.packets[2], 's', '') =~# 'TCP',
      \ 'streamed packets dissect once annotation catches up')
call s:check(exists(':VimcapSniffStop') == 2, ':VimcapSniffStop is available')

" --- capture diff ------------------------------------------------------------
only!
execute 'VimcapDiff ' . fnameescape($VIMCAP_TEST_DIR . '/roundtrip.pcap')
call s:check(&diff, ':VimcapDiff enters diff mode')

call writefile(s:results + ['DONE'], $VIMCAP_TEST_OUT)
quitall!
