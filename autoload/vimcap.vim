" vimcap autoload functions: loading, saving, inspecting and annotating
" packet captures as editable hex.

" ---------------------------------------------------------------------------
" Configuration helpers
" ---------------------------------------------------------------------------

function! s:python() abort
  return get(g:, 'vimcap_python', 'python3')
endfunction

function! s:annotate_limit() abort
  return get(g:, 'vimcap_annotate_limit', 2000)
endfunction

function! s:linktype() abort
  return get(get(b:, 'vimcap', {}), 'linktype', get(g:, 'vimcap_default_linktype', 1))
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

  call s:load_meta()
  call vimcap#init()
  call s:apply_highlights()
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
  call s:apply_highlights()
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
  call s:apply_highlights()
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

  command! -buffer                VimcapAscii    call vimcap#ascii_pane()
  command! -buffer                VimcapUtf8     call vimcap#utf8_pane()
  command! -buffer -nargs=?       VimcapSummary  call vimcap#summary_pane(<q-args>)
  command! -buffer -nargs=?       VimcapDetail   call vimcap#detail(<q-args>)
  command! -buffer                VimcapRefresh  call vimcap#refresh()
  command! -buffer -nargs=1       VimcapGoto     call vimcap#goto_offset(<q-args>)
  command! -buffer -range         VimcapValue    call vimcap#value()

  nnoremap <buffer> <silent> K  :VimcapDetail<CR>
  nnoremap <buffer> <silent> >a :VimcapAscii<CR>
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
    autocmd TextChanged,TextChangedI <buffer> let b:vimcap_stale = 1
  augroup END
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

function! s:apply_highlights() abort
  if !get(g:, 'vimcap_highlight', 1) || !exists('b:vimcap')
    return
  endif
  let bufnr = bufnr('%')

  if has('nvim')
    let ns = nvim_create_namespace('vimcap')
    call nvim_buf_clear_namespace(bufnr, ns, 0, -1)
  elseif has('textprop')
    for depth in range(4)
      if empty(prop_type_get('VimcapLayer' . depth))
        call prop_type_add('VimcapLayer' . depth, {'highlight': 'VimcapLayer' . depth})
      endif
    endfor
    if empty(prop_type_get('VimcapPayload'))
      call prop_type_add('VimcapPayload', {'highlight': 'VimcapPayload'})
    endif
    call prop_clear(1, line('$'), {'bufnr': bufnr})
  else
    return
  endif

  let lnum = 0
  for packet in get(b:vimcap, 'packets', [])
    let lnum += 1
    if lnum > line('$')
      break
    endif
    let depth = 0
    for [start, end, name] in get(packet, 'layers', [])
      let group = s:highlight_group(name, depth)
      " Byte n occupies columns n*3+1 and n*3+2; skip the trailing space.
      if has('nvim')
        call nvim_buf_add_highlight(bufnr, ns, group, lnum - 1, start * 3, end * 3 - 1)
      else
        call prop_add(lnum, start * 3 + 1,
              \ {'length': (end - start) * 3 - 1, 'type': group, 'bufnr': bufnr})
      endif
      let depth += 1
    endfor
  endfor
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

" Show lines in a reusable scratch split. 'bind' syncs scrolling (and the
" cursor, when columns align) with the hex window.
function! s:pane(name, lines, height, bind) abort
  let source_win = win_getid()
  let height = min([a:height, max([3, &lines / 3])])
  let existing = bufnr(a:name)
  let winid = existing > 0 ? bufwinid(existing) : -1
  if winid > 0
    call win_gotoid(winid)
  elseif existing > 0
    execute 'botright ' . height . 'split'
    execute 'buffer' existing
  else
    execute 'botright ' . height . 'new'
    setlocal buftype=nofile bufhidden=wipe noswapfile winfixheight
    silent! execute 'file ' . fnameescape(a:name)
  endif
  setlocal modifiable
  silent keepjumps %delete _
  call setline(1, a:lines)
  setlocal nomodifiable nowrap nonumber
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
  call s:pane(a:name, out, 10, a:bind)
endfunction

function! vimcap#ascii_pane() abort
  call s:filter_pane('vimcap://ascii', 'ascii', 'cursor')
endfunction

function! vimcap#utf8_pane() abort
  call s:filter_pane('vimcap://utf8', 'utf8', 'scroll')
endfunction

function! vimcap#summary_pane(...) abort
  let proto = a:0 && !empty(a:1) ? a:1 : ''
  let packets = get(get(b:, 'vimcap', {}), 'packets', [])
  if empty(proto) && !empty(packets) && !get(b:, 'vimcap_stale', 0)
        \ && len(packets) >= line('$') && has_key(packets[-1], 's')
    " Everything is annotated: build the pane from meta without a subprocess.
    let lines = map(copy(packets), {index, packet ->
          \ printf('%4d  %s', index + 1, get(packet, 's', ''))})
    call s:pane('vimcap://summary', lines, 10, 'scroll')
    return
  endif
  let command = 'summary --linktype ' . s:linktype()
        \ . (empty(proto) ? '' : ' --proto ' . shellescape(proto))
  call s:filter_pane('vimcap://summary', command, 'scroll')
endfunction

function! vimcap#detail(...) abort
  let proto = a:0 && !empty(a:1) ? a:1 : ''
  let command = 'show --linktype ' . s:linktype()
        \ . (empty(proto) ? '' : ' --proto ' . shellescape(proto))
  try
    let out = s:run(command, [getline('.')])
  catch /^vimcap:/
    call s:error(v:exception)
    return
  endtry
  call s:pane('vimcap://detail', out, 15, '')
endfunction
