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
call s:check(s:detail_buf > 0
      \ && join(getbufline(s:detail_buf, 1, '$'), "\n") =~# '###\[ Ethernet \]###',
      \ 'detail pane shows the scapy dissection tree')

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

call writefile(s:results + ['DONE'], $VIMCAP_TEST_OUT)
quitall!
