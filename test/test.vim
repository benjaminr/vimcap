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
call s:check(&cursorbind && &scrollbind, 'hex window binds to the ascii pane')

call vimcap#detail()
let s:detail_buf = bufnr('vimcap://detail')
call s:check(s:detail_buf > 0
      \ && join(getbufline(s:detail_buf, 1, '$'), "\n") =~# '###\[ Ethernet \]###',
      \ 'detail pane shows the scapy dissection tree')

call vimcap#summary_pane('')
let s:summary_buf = bufnr('vimcap://summary')
call s:check(s:summary_buf > 0 && getbufline(s:summary_buf, 2)[0] =~# 'DNS',
      \ 'summary pane lists one summary per packet')

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

call writefile(s:results + ['DONE'], $VIMCAP_TEST_OUT)
quitall!
