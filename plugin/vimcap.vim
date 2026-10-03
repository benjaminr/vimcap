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

" Apply the colour theme now and whenever the colourscheme changes (so a
" later :colorscheme does not blow vimcap's groups away).
call vimcap#theme#apply()

augroup vimcap
  autocmd!
  autocmd ColorScheme * call vimcap#theme#apply()
  autocmd BufReadCmd  *.pcap,*.pcapng,*.cap call vimcap#load(expand('<amatch>'))
  " A new (non-existent) capture: set up an empty session so commands like
  " :VimcapSniff are ready to populate it.
  autocmd BufNewFile  *.pcap,*.pcapng,*.cap call vimcap#load(expand('<amatch>'))
  autocmd BufWriteCmd *.pcap,*.pcapng,*.cap call vimcap#write(expand('<amatch>'))
augroup END

" Available anywhere (not just in a capture buffer).
command! VimcapHealth call vimcap#health()
command! VimcapHelp call vimcap#welcome_toggle()
command! -nargs=? -complete=customlist,vimcap#theme#complete VimcapTheme
      \ call vimcap#theme#set(<q-args>)

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
