" vimcap - edit packet captures as hex, with scapy-powered dissection
" Maintainer:  Benjamin Rowell <brrowell@gmail.com>
" License:     This file is placed in the public domain.

if exists('g:loaded_vimcap') || &compatible
  finish
endif
let g:loaded_vimcap = 1

" Path to the bundled helper script; overridable for development.
let g:vimcap_script = get(g:, 'vimcap_script',
      \ expand('<sfile>:p:h:h') . '/python/vimcap.py')

" Layer colours cycle through these groups; payload bytes get their own.
highlight default link VimcapLayer0 Identifier
highlight default link VimcapLayer1 Statement
highlight default link VimcapLayer2 Type
highlight default link VimcapLayer3 Special
highlight default link VimcapPayload String
highlight default link VimcapCursorByte MatchParen
highlight default link VimcapBitOn Statement
highlight default link VimcapBitOff NonText

augroup vimcap
  autocmd!
  autocmd BufReadCmd  *.pcap,*.pcapng,*.cap call vimcap#load(expand('<amatch>'))
  autocmd BufWriteCmd *.pcap,*.pcapng,*.cap call vimcap#write(expand('<amatch>'))
augroup END

" Diagnostics, available anywhere (not just in a capture buffer).
command! VimcapHealth call vimcap#health()

" Legacy entry points kept for backwards compatibility with old vimcap.
function! LoadPcap(...) abort
  call vimcap#load(a:0 ? a:1 : expand('%:p'))
endfunction

function! WritePcap(...) abort
  call vimcap#write(a:0 ? a:1 : expand('%:p'))
endfunction

function! ScapyPrint(encap) abort
  call vimcap#summary_pane(a:encap)
endfunction

function! HexToAscii() abort
  call vimcap#ascii_pane()
endfunction

function! HexToUni() abort
  call vimcap#utf8_pane()
endfunction
