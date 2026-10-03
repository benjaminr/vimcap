" vimcap themes: one coordinated palette drives every pane, so an IP layer is
" the same colour in the hex bytes, the detail heading and the summary.
"
" A theme is a dict of semantic roles -> [cterm, guihex]. All the concrete
" highlight groups are derived from those roles (see s:apply), so adding a
" theme only means choosing a dozen colours. g:vimcap_theme selects one;
" g:vimcap_themes can add or override themes.

let s:themes = {
      \ 'mono': {
      \   'accent': [44, '#00d7d7'], 'error': [203, '#ff5f5f'],
      \   'bright': [253, '#dadada'], 'normal': [250, '#bcbcbc'],
      \   'dim': [243, '#767676'], 'dimmer': [238, '#444444'],
      \   'l0': [253, '#dadada'], 'l1': [247, '#9e9e9e'],
      \   'l2': [243, '#767676'], 'l3': [240, '#585858'],
      \   'payload': [239, '#4e4e4e']},
      \ 'neon': {
      \   'accent': [51, '#00ffff'], 'error': [197, '#ff005f'],
      \   'bright': [231, '#ffffff'], 'normal': [252, '#d0d0d0'],
      \   'dim': [244, '#808080'], 'dimmer': [238, '#444444'],
      \   'l0': [51, '#00ffff'], 'l1': [48, '#00ff87'],
      \   'l2': [201, '#ff00ff'], 'l3': [214, '#ffaf00'],
      \   'payload': [240, '#585858']},
      \ 'warm': {
      \   'accent': [136, '#af8700'], 'error': [160, '#d70000'],
      \   'bright': [223, '#ffd7af'], 'normal': [180, '#d7af87'],
      \   'dim': [137, '#af875f'], 'dimmer': [101, '#87875f'],
      \   'l0': [37, '#00afaf'], 'l1': [100, '#878700'],
      \   'l2': [168, '#d75f87'], 'l3': [66, '#5f8787'],
      \   'payload': [101, '#87875f']}}

" Each concrete group as [role, attributes]. 'rev' reverses fg/bg (so the
" cursor byte paints a solid block in the accent colour on any background).
let s:groups = {
      \ 'VimcapLayer0': ['l0', ''], 'VimcapLayer1': ['l1', ''],
      \ 'VimcapLayer2': ['l2', ''], 'VimcapLayer3': ['l3', ''],
      \ 'VimcapPayload': ['payload', ''],
      \ 'VimcapCursorByte': ['accent', 'reverse'],
      \ 'VimcapBitOn': ['bright', ''], 'VimcapBitOff': ['dimmer', ''],
      \ 'VimcapHeader': ['accent', 'bold'],
      \ 'VimcapPath': ['normal', ''], 'VimcapPathSep': ['dimmer', ''],
      \ 'VimcapRule': ['dimmer', ''],
      \ 'VimcapLayerName': ['bright', 'bold'],
      \ 'VimcapLayerCurrent': ['accent', 'bold'],
      \ 'VimcapOffset': ['dim', ''], 'VimcapField': ['normal', ''],
      \ 'VimcapValue': ['bright', ''], 'VimcapVendor': ['dim', 'italic'],
      \ 'VimcapBad': ['error', 'bold'],
      \ 'VimcapFieldCursor': ['accent', 'reverse'],
      \ 'VimcapBar': ['accent', ''], 'VimcapBarTrack': ['dimmer', '']}

" 'classic' links everything to standard colourscheme groups instead of
" hard-coding colours, for users who want vimcap to follow their theme.
let s:classic = {
      \ 'VimcapLayer0': 'Identifier', 'VimcapLayer1': 'Statement',
      \ 'VimcapLayer2': 'Type', 'VimcapLayer3': 'Special',
      \ 'VimcapPayload': 'String', 'VimcapCursorByte': 'MatchParen',
      \ 'VimcapBitOn': 'Statement', 'VimcapBitOff': 'NonText',
      \ 'VimcapHeader': 'Title', 'VimcapPath': 'Normal', 'VimcapPathSep': 'Comment',
      \ 'VimcapRule': 'Comment', 'VimcapLayerName': 'Title',
      \ 'VimcapLayerCurrent': 'Search', 'VimcapOffset': 'Comment',
      \ 'VimcapField': 'Identifier', 'VimcapValue': 'Normal',
      \ 'VimcapVendor': 'Comment', 'VimcapBad': 'Error',
      \ 'VimcapFieldCursor': 'CursorLine', 'VimcapBar': 'Statement',
      \ 'VimcapBarTrack': 'NonText'}

function! s:hi(group, colour, attr) abort
  let attr = empty(a:attr) ? 'NONE' : a:attr
  execute 'highlight' a:group
        \ 'cterm=' . attr 'gui=' . attr
        \ 'ctermfg=' . a:colour[0] 'guifg=' . a:colour[1]
endfunction

function! vimcap#theme#names() abort
  return sort(keys(s:themes) + ['classic']
        \ + keys(get(g:, 'vimcap_themes', {})))
endfunction

" :VimcapTheme [name] — switch theme live, or report the current one.
function! vimcap#theme#set(name) abort
  if empty(a:name)
    echo 'vimcap theme: ' . get(g:, 'vimcap_theme', 'mono')
          \ . '  (available: ' . join(vimcap#theme#names(), ', ') . ')'
    return
  endif
  if index(vimcap#theme#names(), a:name) < 0
    echohl ErrorMsg
    echomsg 'vimcap: unknown theme ' . string(a:name)
          \ . '; try one of ' . join(vimcap#theme#names(), ', ')
    echohl None
    return
  endif
  let g:vimcap_theme = a:name
  call vimcap#theme#apply()
  echo 'vimcap theme: ' . a:name
endfunction

function! vimcap#theme#complete(arglead, cmdline, cursorpos) abort
  return filter(vimcap#theme#names(), 'v:val =~# "^" . a:arglead')
endfunction

function! vimcap#theme#apply() abort
  let name = get(g:, 'vimcap_theme', 'mono')

  if name ==# 'classic'
    for [group, target] in items(s:classic)
      execute 'highlight! default link' group target
    endfor
    return
  endif

  let palette = get(get(g:, 'vimcap_themes', {}), name, get(s:themes, name, {}))
  if empty(palette)
    echohl WarningMsg
    echomsg 'vimcap: unknown theme ' . string(name) . '; using mono'
    echohl None
    let palette = s:themes.mono
  endif

  for [group, spec] in items(s:groups)
    let [role, attr] = spec
    call s:hi(group, get(palette, role, palette.normal), attr)
  endfor
endfunction
