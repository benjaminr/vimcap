" vimcap autoload functions: loading, saving, inspecting and annotating
" packet captures as editable hex.

" ---------------------------------------------------------------------------
" Configuration helpers
" ---------------------------------------------------------------------------

function! s:python() abort
  return get(g:, 'vimcap_python', 'python3')
endfunction

function! vimcap#annotate_limit() abort
  return get(g:, 'vimcap_annotate_limit', 2000)
endfunction

function! vimcap#linktype(bufnr) abort
  return get(getbufvar(a:bufnr, 'vimcap', {}), 'linktype',
        \ get(g:, 'vimcap_default_linktype', 1))
endfunction

function! s:annotate_limit() abort
  return vimcap#annotate_limit()
endfunction

function! s:linktype() abort
  return vimcap#linktype(bufnr('%'))
endfunction

" Run the helper script. Returns stdout lines; throws 'vimcap: ...' on error.
function! s:run(args, input) abort
  let errfile = tempname()
  let cmd = s:python() . ' ' . shellescape(g:vimcap_script) . ' ' . a:args
        \ . ' 2>' . shellescape(errfile)
  if a:input is v:null
    let out = systemlist(cmd)
  else
    let out = systemlist(cmd, a:input)
  endif
  let errors = filereadable(errfile) ? readfile(errfile) : []
  call delete(errfile)
  if v:shell_error
    let detail = filter(copy(errors), 'v:val =~# "vimcap:"')
    throw empty(detail)
          \ ? 'vimcap: helper failed (exit ' . v:shell_error . '): ' . join(errors[-2:], ' ')
          \ : join(detail, ' ')
  endif
  " Surface the helper's non-fatal warnings (e.g. pcapng written as pcap).
  for line in filter(errors, 'v:val =~# "vimcap:"')
    echohl WarningMsg | echomsg line | echohl None
  endfor
  return out
endfunction

function! s:error(message) abort
  echohl ErrorMsg | echomsg a:message | echohl None
endfunction

" ---------------------------------------------------------------------------
" Loading and saving
" ---------------------------------------------------------------------------

function! vimcap#load(path) abort
  if !exists('b:vimcap_meta_file')
    let b:vimcap_meta_file = tempname() . '.json'
  endif
  let lines = []
  if filereadable(a:path)
    try
      let lines = s:run('load ' . shellescape(a:path)
            \ . ' --meta ' . shellescape(b:vimcap_meta_file)
            \ . ' --limit ' . s:annotate_limit(), v:null)
    catch /^vimcap:/
      call s:error(v:exception)
      return
    endtry
  endif

  " Replace the buffer without polluting the undo history.
  let saved_undolevels = &l:undolevels
  setlocal undolevels=-1
  silent keepjumps %delete _
  if !empty(lines)
    call setline(1, lines)
  endif
  let &l:undolevels = saved_undolevels
  setlocal nomodified
  let b:vimcap_lines = getline(1, '$')

  call s:load_meta()
  call vimcap#init()
  call vimcap#apply_highlights(bufnr('%'))

  " Panes that open along with the capture; K puts the dissection away.
  if line('$') > 0 && !empty(getline(1))
    for pane in get(g:, 'vimcap_auto_panes', ['detail', 'ascii', 'bits'])
      if bufwinid(bufnr('vimcap://' . pane)) > 0
        continue
      endif
      if pane ==# 'detail'
        call vimcap#detail()
      elseif pane ==# 'ascii'
        call vimcap#ascii_pane()
      elseif pane ==# 'bits'
        call vimcap#bits_pane()
      elseif pane ==# 'summary'
        call vimcap#summary_pane('')
      elseif pane ==# 'utf8'
        call vimcap#utf8_pane()
      endif
    endfor
  endif
  call vimcap#update_panes(bufnr('%'))
endfunction

function! vimcap#write(path) abort
  let meta_arg = exists('b:vimcap_meta_file')
        \ ? ' --meta ' . shellescape(b:vimcap_meta_file) : ''
  try
    let out = s:run('save ' . shellescape(a:path) . meta_arg
          \ . ' --linktype ' . s:linktype()
          \ . ' --limit ' . s:annotate_limit(), getline(1, '$'))
  catch /^vimcap:/
    call s:error(v:exception)
    return
  endtry
  if fnamemodify(a:path, ':p') ==# expand('%:p')
    setlocal nomodified
  endif
  call s:load_meta()
  let b:vimcap_stale = 0
  let b:vimcap_lines = getline(1, '$')
  call vimcap#apply_highlights(bufnr('%'))
  echo printf('"%s" %s written', a:path, get(out, 0, ''))
endfunction

function! vimcap#refresh() abort
  if !exists('b:vimcap_meta_file')
    let b:vimcap_meta_file = tempname() . '.json'
  endif
  try
    call s:run('annotate --meta ' . shellescape(b:vimcap_meta_file)
          \ . ' --linktype ' . s:linktype()
          \ . ' --limit ' . s:annotate_limit(), getline(1, '$'))
  catch /^vimcap:/
    call s:error(v:exception)
    return
  endtry
  call s:load_meta()
  let b:vimcap_stale = 0
  let b:vimcap_lines = getline(1, '$')
  call vimcap#apply_highlights(bufnr('%'))
  call vimcap#update_panes(bufnr('%'))
endfunction

function! s:load_meta() abort
  let b:vimcap = {'linktype': get(g:, 'vimcap_default_linktype', 1), 'packets': []}
  if exists('b:vimcap_meta_file') && filereadable(b:vimcap_meta_file)
    try
      let b:vimcap = json_decode(join(readfile(b:vimcap_meta_file), ''))
    catch
    endtry
  endif
endfunction

" ---------------------------------------------------------------------------
" Buffer setup
" ---------------------------------------------------------------------------

function! vimcap#init() abort
  setlocal filetype=vimcap
  setlocal number nowrap nostartofline noswapfile
  setlocal cursorline cursorcolumn
  setlocal formatoptions-=t
  " Hex digits form a 'word' so \k motions and the cursor-byte match work.
  setlocal iskeyword=48-57,65-70,97-102

  if get(g:, 'vimcap_statusline', 1)
    setlocal statusline=%!vimcap#statusline()
  endif

  " Let the mouse scroll and focus the panes, unless the user has their own
  " preference ('mouse' is global, so only touch it when unset).
  if get(g:, 'vimcap_mouse', 1) && empty(&mouse)
    set mouse=a
  endif

  command! -buffer                VimcapAscii    call vimcap#ascii_pane()
  command! -buffer                VimcapBits     call vimcap#bits_pane()
  command! -buffer                VimcapUtf8     call vimcap#utf8_pane()
  command! -buffer -nargs=?       VimcapSummary  call vimcap#summary_pane(<q-args>)
  command! -buffer -nargs=?       VimcapDetail   call vimcap#detail(<q-args>)
  command! -buffer                VimcapRefresh  call vimcap#refresh()
  command! -buffer -nargs=1       VimcapGoto     call vimcap#goto_offset(<q-args>)
  command! -buffer -range         VimcapValue    call vimcap#value()

  nnoremap <buffer> <silent> K  :call vimcap#detail_toggle()<CR>
  nnoremap <buffer> <silent> >a :VimcapAscii<CR>
  nnoremap <buffer> <silent> >b :VimcapBits<CR>
  nnoremap <buffer> <silent> >u :VimcapUtf8<CR>
  nnoremap <buffer> <silent> >s :VimcapSummary<CR>
  xnoremap <buffer> <silent> K :VimcapValue<CR>

  if get(g:, 'vimcap_byte_motions', 1)
    " Move by bytes rather than characters; words become protocol fields.
    nnoremap <buffer> h 3h
    nnoremap <buffer> l 3l
    nnoremap <buffer> <silent> w :call vimcap#field_jump(1)<CR>
    nnoremap <buffer> <silent> b :call vimcap#field_jump(-1)<CR>
  endif

  call s:ensure_cursor_match()
  augroup vimcap_buffer
    autocmd! * <buffer>
    autocmd BufWinEnter,WinEnter <buffer> call s:ensure_cursor_match()
    autocmd TextChanged,TextChangedI <buffer> call vimcap#live#on_change()
    autocmd CursorMoved <buffer> call vimcap#track_cursor()
  augroup END
  call vimcap#live#warm()
endfunction

" Highlight both hex digits of the byte under the cursor, per window.
function! s:ensure_cursor_match() abort
  if !exists('w:vimcap_cursor_match')
    let w:vimcap_cursor_match = matchadd('VimcapCursorByte', '\k*\%#\k*')
  endif
endfunction

" ---------------------------------------------------------------------------
" Layer highlighting
" ---------------------------------------------------------------------------

function! s:highlight_group(name, depth) abort
  if index(['Raw', 'Padding'], a:name) >= 0
    return 'VimcapPayload'
  endif
  return 'VimcapLayer' . (a:depth % 4)
endfunction

" Prepare highlight machinery; returns the namespace id (Neovim), 0 for
" text properties (Vim) or -1 when no mechanism is available.
function! s:highlight_namespace() abort
  if has('nvim')
    return nvim_create_namespace('vimcap')
  endif
  if !has('textprop')
    return -1
  endif
  for group in ['VimcapLayer0', 'VimcapLayer1', 'VimcapLayer2', 'VimcapLayer3',
        \ 'VimcapPayload']
    if empty(prop_type_get(group))
      call prop_type_add(group, {'highlight': group})
    endif
  endfor
  return 0
endfunction

function! s:paint_line(bufnr, ns, lnum, packet) abort
  let depth = 0
  for [start, end, name] in get(a:packet, 'layers', [])
    let group = s:highlight_group(name, depth)
    " Byte n occupies columns n*3+1 and n*3+2; skip the trailing space.
    if has('nvim')
      silent! call nvim_buf_add_highlight(a:bufnr, a:ns, group,
            \ a:lnum - 1, start * 3, end * 3 - 1)
    else
      silent! call prop_add(a:lnum, start * 3 + 1,
            \ {'length': (end - start) * 3 - 1, 'type': group, 'bufnr': a:bufnr})
    endif
    let depth += 1
  endfor
endfunction

function! vimcap#apply_highlights(bufnr) abort
  if !get(g:, 'vimcap_highlight', 1)
    return
  endif
  let ns = s:highlight_namespace()
  if ns < 0
    return
  endif
  let last = len(getbufline(a:bufnr, 1, '$'))
  if has('nvim')
    call nvim_buf_clear_namespace(a:bufnr, ns, 0, -1)
  else
    call prop_clear(1, max([last, 1]), {'bufnr': a:bufnr})
  endif
  let lnum = 0
  for packet in get(getbufvar(a:bufnr, 'vimcap', {}), 'packets', [])
    let lnum += 1
    if lnum > last
      break
    endif
    call s:paint_line(a:bufnr, ns, lnum, packet)
  endfor
endfunction

function! vimcap#highlight_line(bufnr, lnum) abort
  if !get(g:, 'vimcap_highlight', 1)
    return
  endif
  let packets = get(getbufvar(a:bufnr, 'vimcap', {}), 'packets', [])
  if a:lnum > len(packets)
    return
  endif
  let ns = s:highlight_namespace()
  if ns < 0
    return
  endif
  if has('nvim')
    call nvim_buf_clear_namespace(a:bufnr, ns, a:lnum - 1, a:lnum)
  else
    call prop_clear(a:lnum, a:lnum, {'bufnr': a:bufnr})
  endif
  call s:paint_line(a:bufnr, ns, a:lnum, packets[a:lnum - 1])
endfunction

" ---------------------------------------------------------------------------
" Byte and field inspection
" ---------------------------------------------------------------------------

function! s:cursor_byte() abort
  return (virtcol('.') - 1) / 3
endfunction

function! s:packet_meta(lnum) abort
  let packets = get(get(b:, 'vimcap', {}), 'packets', [])
  return a:lnum <= len(packets) ? packets[a:lnum - 1] : {}
endfunction

" Human description of the byte at (lnum, byte): deepest matching field,
" falling back to the owning layer.
function! s:describe_byte(lnum, byte) abort
  let packet = s:packet_meta(a:lnum)
  let found = ''
  for [start, end, layer, name, value] in get(packet, 'fields', [])
    if a:byte >= start && a:byte < end
      let found = printf('%s.%s = %s', layer, name, value)
    endif
  endfor
  if !empty(found)
    return found
  endif
  for [start, end, name] in get(packet, 'layers', [])
    if a:byte >= start && a:byte < end
      let found = name
    endif
  endfor
  return found
endfunction

function! vimcap#statusline() abort
  let byte = s:cursor_byte()
  let info = s:describe_byte(line('.'), byte)
  let stale = get(b:, 'vimcap_stale', 0) ? '  [edited - :VimcapRefresh]' : ''
  return ' %f %m pkt %l/%L  byte ' . printf('0x%02X', byte)
        \ . (empty(info) ? '' : '  ' . substitute(info, '%', '%%', 'g'))
        \ . stale . '%= linktype ' . s:linktype() . ' '
endfunction

" Jump to the next (direction=1) or previous (direction=-1) field boundary,
" treating protocol fields as 'words'. Falls back to 4-byte hops when the
" packet has no annotations.
function! vimcap#field_jump(direction) abort
  let byte = s:cursor_byte()
  let starts = []
  for [start, end, layer, name, value] in get(s:packet_meta(line('.')), 'fields', [])
    if index(starts, start) < 0
      call add(starts, start)
    endif
  endfor
  if empty(starts)
    let target = max([0, byte + a:direction * 4])
  else
    call sort(starts, 'n')
    let target = -1
    for start in (a:direction > 0 ? starts : reverse(copy(starts)))
      if (a:direction > 0 && start > byte) || (a:direction < 0 && start < byte)
        let target = start
        break
      endif
    endfor
    if target < 0
      " Step over the packet boundary to the adjacent line.
      let next = line('.') + a:direction
      if next >= 1 && next <= line('$')
        call cursor(next, 1)
        if a:direction < 0
          call cursor(next, max([1, virtcol('$') - 2]))
        endif
      endif
      return
    endif
  endif
  call cursor(line('.'), target * 3 + 1)
endfunction

function! vimcap#goto_offset(offset) abort
  let byte = a:offset =~? '^0x' ? str2nr(a:offset[2:], 16) : str2nr(a:offset)
  call cursor(line('.'), byte * 3 + 1)
endfunction

" Interpret the visually selected bytes as integers and text.
function! vimcap#value() abort
  if line("'<") != line("'>")
    call s:error('vimcap: select bytes on a single line')
    return
  endif
  let bytes = split(getline("'<"))
  let first = (virtcol("'<") - 1) / 3
  let last = min([(virtcol("'>") - 1) / 3, len(bytes) - 1])
  let selected = bytes[first : last]
  let total = len(selected)

  let text = ''
  for pair in selected
    let code = str2nr(pair, 16)
    let text .= (code >= 32 && code < 127) ? nr2char(code) : '.'
  endfor

  let message = printf('%d byte%s  0x%s  "%s"',
        \ total, total == 1 ? '' : 's', join(selected, ''), text)
  if total <= 8
    let [big, little] = [0, 0]
    for index in range(total)
      let big = big * 256 + str2nr(selected[index], 16)
      let little = little * 256 + str2nr(selected[total - 1 - index], 16)
    endfor
    let message .= printf('  BE %d  LE %d', big, little)
  endif
  echo message
endfunction

" ---------------------------------------------------------------------------
" Panes: ascii / utf8 / summary / detail
" ---------------------------------------------------------------------------

" Byte-aligned views sit under the hex window; dissection views live in a
" shared right-hand column.
let s:column_panes = ['vimcap://detail', 'vimcap://summary']

" The window of any open column pane, so a new one stacks beneath it.
function! s:column_window() abort
  for name in s:column_panes
    let winid = bufwinid(bufnr(name))
    if winid > 0
      return winid
    endif
  endfor
  return -1
endfunction

function! s:open_pane_window(name, existing) abort
  if index(s:column_panes, a:name) < 0
    " Bottom pane, column-aligned with the hex window.
    let height = min([10, max([3, &lines / 3])])
    if a:existing > 0
      execute 'botright ' . height . 'sbuffer' a:existing
    else
      execute 'botright ' . height . 'new'
    endif
    setlocal winfixheight
  else
    let column = s:column_window()
    if column > 0
      call win_gotoid(column)
      if a:existing > 0
        execute 'belowright sbuffer' a:existing
      else
        belowright new
      endif
    else
      let width = min([get(g:, 'vimcap_pane_width', 64), &columns / 2])
      if a:existing > 0
        execute 'botright vertical sbuffer' a:existing
      else
        botright vnew
      endif
      execute 'vertical resize' width
    endif
    setlocal winfixwidth
  endif
  if a:existing < 0
    setlocal buftype=nofile bufhidden=wipe noswapfile
    silent! execute 'file ' . fnameescape(a:name)
  endif
  setlocal nonumber
endfunction

" Show lines in a reusable scratch pane. 'bind' syncs scrolling (and the
" cursor, when columns align) with the hex window.
function! s:pane(name, lines, bind) abort
  let source_win = win_getid()
  let existing = bufnr(a:name)
  let winid = existing > 0 ? bufwinid(existing) : -1
  if winid > 0
    call win_gotoid(winid)
  else
    call s:open_pane_window(a:name, existing)
  endif
  setlocal modifiable
  silent keepjumps %delete _
  call setline(1, a:lines)
  setlocal nomodifiable nowrap
  if a:bind ==# 'cursor'
    setlocal cursorbind scrollbind cursorline cursorcolumn
  elseif a:bind ==# 'scroll'
    setlocal scrollbind cursorline
  endif
  call win_gotoid(source_win)
  if a:bind !=# ''
    setlocal scrollbind
    if a:bind ==# 'cursor'
      setlocal cursorbind
    endif
  endif
endfunction

function! s:filter_pane(name, command, bind) abort
  try
    let out = s:run(a:command, getline(1, '$'))
  catch /^vimcap:/
    call s:error(v:exception)
    return
  endtry
  call s:pane(a:name, out, a:bind)
endfunction

" Replace an open pane's contents in place, leaving the window layout and
" cursor alone. Does nothing when the pane is not on screen.
function! s:sync_pane(name, lines) abort
  let pane = bufnr(a:name)
  if pane < 0 || bufwinid(pane) < 0
    return
  endif
  call setbufvar(pane, '&modifiable', 1)
  call setbufline(pane, 1, a:lines)
  if getbufinfo(pane)[0].linecount > len(a:lines)
    silent call deletebufline(pane, len(a:lines) + 1, '$')
  endif
  call setbufvar(pane, '&modifiable', 0)
endfunction

function! s:ascii_line(hexline) abort
  let chars = []
  for pair in split(a:hexline)
    let code = str2nr(pair, 16)
    call add(chars, (code >= 32 && code < 127) ? nr2char(code) : '.')
  endfor
  return join(chars, '  ')
endfunction

function! s:ascii_lines(bufnr) abort
  return map(getbufline(a:bufnr, 1, '$'), {_, line -> s:ascii_line(line)})
endfunction

" One byte becomes eight block glyphs, most significant bit first.
let s:bit_weights = [128, 64, 32, 16, 8, 4, 2, 1]

function! s:bits_line(hexline) abort
  let groups = []
  for pair in split(a:hexline)
    let value = str2nr(pair, 16)
    let bits = ''
    for weight in s:bit_weights
      let bits .= and(value, weight) ? '█' : '·'
    endfor
    call add(groups, bits)
  endfor
  return join(groups, ' ')
endfunction

function! s:bits_lines(bufnr) abort
  return map(getbufline(a:bufnr, 1, '$'), {_, line -> s:bits_line(line)})
endfunction

function! s:summary_lines(bufnr) abort
  let packets = get(getbufvar(a:bufnr, 'vimcap', {}), 'packets', [])
  return map(copy(packets),
        \ {index, packet -> printf('%4d  %s', index + 1, get(packet, 's', ''))})
endfunction

function! vimcap#ascii_pane() abort
  call s:pane('vimcap://ascii', s:ascii_lines(bufnr('%')), 'scroll')
endfunction

function! vimcap#utf8_pane() abort
  call s:filter_pane('vimcap://utf8', 'utf8', 'scroll')
endfunction

function! vimcap#bits_pane() abort
  call s:pane('vimcap://bits', s:bits_lines(bufnr('%')), 'scroll')
  let winid = bufwinid(bufnr('vimcap://bits'))
  if winid > 0
    call win_execute(winid, 'if !get(b:, "vimcap_bits_syntax", 0)'
          \ . ' | syntax match VimcapBitOn /█\+/'
          \ . ' | syntax match VimcapBitOff /·\+/'
          \ . ' | let b:vimcap_bits_syntax = 1 | endif')
  endif
endfunction

" Bring every open pane in line with the buffer's current bytes and
" annotations. Called after live updates and :VimcapRefresh.
function! vimcap#update_panes(bufnr) abort
  call s:sync_pane('vimcap://ascii', s:ascii_lines(a:bufnr))
  call s:sync_pane('vimcap://bits', s:bits_lines(a:bufnr))
  call s:sync_pane('vimcap://summary', s:summary_lines(a:bufnr))
  let hexwin = bufwinid(a:bufnr)
  if hexwin > 0 && bufwinid(bufnr('vimcap://detail')) > 0
    call s:sync_pane('vimcap://detail', s:detail_lines(a:bufnr,
          \ line('.', hexwin), getbufvar(a:bufnr, 'vimcap_detail_proto', '')))
  endif
endfunction

function! vimcap#summary_pane(...) abort
  let proto = a:0 && !empty(a:1) ? a:1 : ''
  let packets = get(get(b:, 'vimcap', {}), 'packets', [])
  if empty(proto) && !empty(packets) && !get(b:, 'vimcap_stale', 0)
        \ && len(packets) >= line('$') && has_key(packets[-1], 's')
    " Everything is annotated: build the pane from meta without a subprocess.
    call s:pane('vimcap://summary', s:summary_lines(bufnr('%')), 'scroll')
    return
  endif
  let command = 'summary --linktype ' . s:linktype()
        \ . (empty(proto) ? '' : ' --proto ' . shellescape(proto))
  call s:filter_pane('vimcap://summary', command, 'scroll')
endfunction

" Dissection tree for one packet, via the live daemon when available,
" otherwise through a helper subprocess.
function! s:detail_lines(bufnr, lnum, proto) abort
  let hexline = get(getbufline(a:bufnr, a:lnum), 0, '')
  let linktype = vimcap#linktype(a:bufnr)
  if vimcap#live#available()
    let lines = vimcap#live#show(linktype, hexline, a:proto)
    if !empty(lines)
      return lines
    endif
  endif
  try
    return s:run('show --linktype ' . linktype
          \ . (empty(a:proto) ? '' : ' --proto ' . shellescape(a:proto)),
          \ [hexline])
  catch /^vimcap:/
    return [v:exception]
  endtry
endfunction

function! vimcap#detail(...) abort
  let b:vimcap_detail_proto = a:0 && !empty(a:1) ? a:1 : ''
  let b:vimcap_detail_lnum = line('.')
  call s:pane('vimcap://detail',
        \ s:detail_lines(bufnr('%'), line('.'), b:vimcap_detail_proto), '')
endfunction

" K: show the dissection pane, or put it away if it is already showing.
function! vimcap#detail_toggle() abort
  let winid = bufwinid(bufnr('vimcap://detail'))
  if winid > 0
    call win_execute(winid, 'close')
  else
    call vimcap#detail()
  endif
endfunction

" Keep every open view pointed at the byte under the cursor: the ascii pane
" at three screen columns per byte, the bits pane at nine, while the summary
" and UTF-8 panes follow the packet line.
function! vimcap#track_cursor() abort
  let lnum = line('.')
  let byte = s:cursor_byte()
  call s:track_pane('vimcap://ascii', lnum, byte * 3, 1)
  call s:track_pane('vimcap://bits', lnum, byte * 9, 8)
  call s:track_pane('vimcap://summary', lnum, -1, 0)
  call s:track_pane('vimcap://utf8', lnum, -1, 0)
  call vimcap#detail_follow()
endfunction

" Move a pane's cursor to the packet line and, when chars >= 0, to that
" character column, highlighting matchlen characters there.
function! s:track_pane(name, lnum, chars, matchlen) abort
  let winid = bufwinid(bufnr(a:name))
  if winid < 0
    return
  endif
  let commands = ['call cursor(' . a:lnum . ', 1)']
  if a:chars > 0
    call add(commands, 'execute "normal! ' . a:chars . 'l"')
  endif
  if a:matchlen > 0
    " Highlight the tracked byte; \%Nv anchors survive multibyte glyphs.
    let pattern = '\%' . a:lnum . 'l\%' . (a:chars + 1) . 'v.\{' . a:matchlen . '}'
    call add(commands, 'if get(w:, "vimcap_track", -1) != -1'
          \ . ' | silent! call matchdelete(w:vimcap_track) | endif')
    call add(commands, 'let w:vimcap_track = matchadd("VimcapCursorByte", '
          \ . string(pattern) . ')')
  endif
  call win_execute(winid, commands)
endfunction

" While the detail pane is open, keep it on the packet under the cursor.
" Only runs through the daemon: a subprocess per cursor move would crawl.
function! vimcap#detail_follow() abort
  let pane = bufnr('vimcap://detail')
  if pane < 0 || bufwinid(pane) < 0
        \ || get(b:, 'vimcap_detail_lnum', -1) == line('.')
        \ || !vimcap#live#available()
    return
  endif
  let b:vimcap_detail_lnum = line('.')
  call s:sync_pane('vimcap://detail', s:detail_lines(bufnr('%'), line('.'),
        \ get(b:, 'vimcap_detail_proto', '')))
endfunction
