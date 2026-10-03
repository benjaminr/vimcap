" vimcap autoload functions: loading, saving, inspecting and annotating
" packet captures as editable hex.

" ---------------------------------------------------------------------------
" Configuration helpers
" ---------------------------------------------------------------------------

" Does this interpreter import scapy? Cached per interpreter string.
function! s:has_scapy(python) abort
  if !exists('s:scapy_cache')
    let s:scapy_cache = {}
  endif
  if !has_key(s:scapy_cache, a:python)
    call system(a:python . ' -c ' . shellescape('import scapy'))
    let s:scapy_cache[a:python] = !v:shell_error
  endif
  return s:scapy_cache[a:python]
endfunction

" Candidate interpreters, best first: an explicit setting always wins; then
" the bundled venv from install.sh; then whatever python is on PATH.
function! s:python_candidates() abort
  if !empty(get(g:, 'vimcap_python', ''))
    return [g:vimcap_python]
  endif
  let venv = fnamemodify(g:vimcap_script, ':h:h') . '/.venv/bin/python'
  return filter([venv, 'python3', 'python'],
        \ 'v:val ==# "python3" || v:val ==# "python" || filereadable(v:val)')
endfunction

" The interpreter the helper runs under. When g:vimcap_python is unset, pick
" the first candidate that has scapy (so dissection just works), falling back
" to the first that merely runs (the pure-Python hex editor still works).
function! s:python() abort
  if !empty(get(g:, 'vimcap_python', ''))
    return g:vimcap_python
  endif
  if exists('s:resolved_python')
    return s:resolved_python
  endif
  let candidates = s:python_candidates()
  for python in candidates
    if s:has_scapy(python)
      let s:resolved_python = python
      return python
    endif
  endfor
  let s:resolved_python = get(candidates, 0, 'python3')
  return s:resolved_python
endfunction

" Public accessor so the live daemon and agent bridge use the same resolved
" interpreter as everything else (not a hardcoded python3 that may lack scapy).
function! vimcap#python() abort
  return s:python()
endfunction

function! vimcap#annotate_limit() abort
  return get(g:, 'vimcap_annotate_limit', 2000)
endfunction

" ---------------------------------------------------------------------------
" Shared pane / geometry helpers
" ---------------------------------------------------------------------------

" The on-screen window id for a pane ('detail', 'ascii', ...), or -1 when the
" pane is not open. The single place pane windows are resolved by name.
function! s:pane_winid(name) abort
  return bufwinid(bufnr('vimcap://' . a:name))
endfunction

" Hex-view screen column of byte N (three columns per byte: two digits + space).
function! s:hexcol(byte) abort
  return a:byte * 3 + 1
endfunction

" Apply buffer-local syntax once per pane: resolve the window, bail if closed
" or already done, set the flag, and run the syntax commands there.
function! s:apply_pane_syntax(name, flag, cmds) abort
  let winid = s:pane_winid(a:name)
  if winid <= 0 || getbufvar(bufnr('vimcap://' . a:name), a:flag, 0)
    return
  endif
  call setbufvar(bufnr('vimcap://' . a:name), a:flag, 1)
  call win_execute(winid, a:cmds)
endfunction

" Show a pane via Builder, or close it if it is already open (K, >?).
function! s:toggle_pane(name, Builder) abort
  let winid = s:pane_winid(a:name)
  if winid > 0
    call win_execute(winid, 'close')
  else
    call call(a:Builder, [])
  endif
endfunction

" Report the environment vimcap depends on, for quick diagnosis.
function! vimcap#health() abort
  let lines = ['vimcap health', '']

  let feats = has('nvim')
        \ ? ['nvim ' . (has('nvim-0.5') ? 'OK' : '(old)')]
        \ : map(['terminal', 'channel', 'textprop'],
        \       {_, f -> f . (has(f) ? '+' : '-')})
  call add(lines, 'editor:  ' . join(feats, ' '))

  let python = s:python()
  let pyver = substitute(system(python . ' --version'), '\n', '', 'g')
  if v:shell_error
    call add(lines, 'python:  ' . python . '  NOT RUNNABLE')
  else
    let scapy = s:has_scapy(python)
          \ ? substitute(system(python . ' -c '
          \     . shellescape('import scapy;print(scapy.__version__)')), '\n', '', 'g')
          \ : 'missing (hex editor works; run install.sh for dissection)'
    call add(lines, 'python:  ' . python . '  (' . pyver . ')')
    call add(lines, 'scapy:   ' . scapy)
  endif

  let agent = get(g:, 'vimcap_agent_cmd', 'claude')
  call add(lines, 'agent:   ' . agent
        \ . (executable(agent) ? '  found' : '  not found (:VimcapAgent unavailable)'))

  echo join(lines, "\n")
endfunction

function! vimcap#linktype(bufnr) abort
  return get(getbufvar(a:bufnr, 'vimcap', {}), 'linktype',
        \ get(g:, 'vimcap_default_linktype', 1))
endfunction

function! s:linktype() abort
  return vimcap#linktype(bufnr('%'))
endfunction

" The annotated packet list for a buffer (empty when none loaded).
function! s:packets(bufnr) abort
  return get(getbufvar(a:bufnr, 'vimcap', {}), 'packets', [])
endfunction

" Per-packet timestamps / wire lengths carried in the meta, for annotation
" requests that must preserve them. Public so the agent bridge can reuse them.
function! vimcap#packet_times(bufnr) abort
  return map(copy(s:packets(a:bufnr)), {_, p -> get(p, 't', '0')})
endfunction

function! vimcap#packet_wirelens(bufnr) abort
  return map(copy(s:packets(a:bufnr)), {_, p -> get(p, 'wl', 0)})
endfunction

function! vimcap#packet_caplens(bufnr) abort
  return map(copy(s:packets(a:bufnr)), {_, p -> get(p, 'cl', get(p, 'wl', 0))})
endfunction

function! vimcap#packet_summaries(bufnr) abort
  return map(copy(s:packets(a:bufnr)), {_, p -> get(p, 's', '')})
endfunction

function! s:ensure_meta_file() abort
  if !exists('b:vimcap_meta_file')
    let b:vimcap_meta_file = tempname() . '.json'
  endif
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
  call s:ensure_meta_file()
  let lines = []
  if filereadable(a:path)
    try
      let lines = s:run('load ' . shellescape(a:path)
            \ . ' --meta ' . shellescape(b:vimcap_meta_file)
            \ . ' --limit ' . vimcap#annotate_limit(), v:null)
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
  call vimcap#open_workspace()

  " An empty session (e.g. a new capture before sniffing) gets the welcome
  " splash — there is nothing else to show, and it says what to do next.
  if get(g:, 'vimcap_welcome', 1) && (line('$') == 0 || empty(getline(1)))
        \ && s:pane_winid('help') < 0
    call vimcap#welcome()
  endif

  " Prime the cursor-byte highlight and pane sync for the initial position.
  if line('$') > 0 && !empty(getline(1))
    call vimcap#track_cursor()
  endif
endfunction

" Open the configured panes (and, if enabled, the agent) for the current
" capture, in order. Does nothing while the buffer is empty, so it can be
" called again once packets arrive — e.g. after sniffing into a new session.
" Idempotent: panes already open are left in place and just refreshed.
function! vimcap#open_workspace() abort
  if line('$') <= 0 || empty(getline(1))
    return
  endif
  for pane in vimcap#auto_panes()
    if s:pane_winid(pane) <= 0
      call s:open_named_pane(pane)
    endif
  endfor
  call vimcap#update_panes(bufnr('%'))
  if get(g:, 'vimcap_auto_agent', 0)
    call vimcap#agent#auto()
  endif
endfunction

function! vimcap#write(path) abort
  let meta_arg = exists('b:vimcap_meta_file')
        \ ? ' --meta ' . shellescape(b:vimcap_meta_file) : ''
  try
    let out = s:run('save ' . shellescape(a:path) . meta_arg
          \ . ' --linktype ' . s:linktype()
          \ . ' --limit ' . vimcap#annotate_limit(), getline(1, '$'))
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
  call s:ensure_meta_file()
  try
    call s:run('annotate --meta ' . shellescape(b:vimcap_meta_file)
          \ . ' --linktype ' . s:linktype()
          \ . ' --limit ' . vimcap#annotate_limit(), getline(1, '$'))
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
  " 'cursorline' is cheap; 'cursorcolumn' forces a full-window redraw on every
  " horizontal move (laggy on large captures), so it is opt-in. The byte under
  " the cursor is already highlighted by the VimcapCursorByte match.
  setlocal cursorline
  if get(g:, 'vimcap_cursorcolumn', 0)
    setlocal cursorcolumn
  endif
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
  command! -buffer                VimcapClose    call vimcap#close_panes()
  command! -buffer                VimcapZoom     call vimcap#zoom()
  command! -buffer -nargs=1       VimcapGoto     call vimcap#goto_offset(<q-args>)
  command! -buffer -range         VimcapValue    call vimcap#value()
  command! -buffer -range=%       VimcapFix      call vimcap#fix(<line1>, <line2>)
  command! -buffer -nargs=1       VimcapSet      call vimcap#set_field(<q-args>)
  command! -buffer -nargs=1       VimcapNew      call vimcap#craft(<q-args>)
  command! -buffer                VimcapCommand  call vimcap#command_string()
  command! -buffer -bang -nargs=? VimcapFilter   call vimcap#filter(<bang>0, <q-args>)
  command! -buffer                VimcapFollow   call vimcap#follow()
  command! -buffer -nargs=1       VimcapGrep     call vimcap#grep(<q-args>)
  command! -buffer                VimcapStats    call vimcap#stats()
  command! -buffer                VimcapAnon     call vimcap#anonymise()
  command! -buffer -nargs=+       VimcapSniff    call vimcap#sniff(<q-args>)
  command! -buffer                VimcapSniffStop call vimcap#sniff_stop()
  command! -buffer -range=% -nargs=? VimcapSend  call vimcap#send(<line1>, <line2>, <q-args>)
  command! -buffer -nargs=1 -complete=file VimcapDiff call vimcap#diff(<q-args>)
  command! -buffer -bang -nargs=? VimcapAgent call vimcap#agent#start(<bang>0, <q-args>)

  nnoremap <buffer> <silent> K  :call vimcap#detail_toggle()<CR>
  nnoremap <buffer> <silent> >a :VimcapAscii<CR>
  nnoremap <buffer> <silent> >b :VimcapBits<CR>
  nnoremap <buffer> <silent> >u :VimcapUtf8<CR>
  nnoremap <buffer> <silent> >s :VimcapSummary<CR>
  nnoremap <buffer> <silent> >q :VimcapClose<CR>
  nnoremap <buffer> <silent> >? :call vimcap#welcome_toggle()<CR>
  nnoremap <buffer> <silent> >z :call vimcap#zoom()<CR>
  nnoremap <buffer> <silent> <Tab> :call vimcap#zoom()<CR>
  " Single-key close too: >q can lag behind Vim's '>' indent operator.
  nnoremap <buffer> <silent> Q  :VimcapClose<CR>
  nnoremap <buffer> <silent> >f :call vimcap#set_prompt()<CR>
  xnoremap <buffer> <silent> K :VimcapValue<CR>

  if get(g:, 'vimcap_byte_motions', 1)
    " Move by bytes rather than characters; words become protocol fields.
    nnoremap <buffer> h 3h
    nnoremap <buffer> l 3l
    nnoremap <buffer> <silent> w :call vimcap#field_jump(1)<CR>
    nnoremap <buffer> <silent> b :call vimcap#field_jump(-1)<CR>
  endif

  augroup vimcap_buffer
    autocmd! * <buffer>
    autocmd TextChanged,TextChangedI <buffer> call vimcap#live#on_change()
    autocmd CursorMoved <buffer> call vimcap#track_cursor()
  augroup END
  call vimcap#live#warm()
endfunction

" Highlight the two hex digits of the byte under the cursor in the hex window.
" Driven from do_track with an explicit position (not a \%# pattern, which
" would force a full-window redraw on every cursor move).
function! s:highlight_cursor_byte(lnum, byte) abort
  if exists('w:vimcap_cursor_match')
    silent! call matchdelete(w:vimcap_cursor_match)
  endif
  let w:vimcap_cursor_match = matchaddpos('VimcapCursorByte', [[a:lnum, s:hexcol(a:byte), 2]])
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
  for packet in s:packets(a:bufnr)
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
  let packets = s:packets(a:bufnr)
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
  let packets = s:packets(bufnr('%'))
  return a:lnum <= len(packets) ? packets[a:lnum - 1] : {}
endfunction

" Description of a byte within a packet's meta: deepest matching field,
" falling back to the owning layer.
function! s:describe_in(packet, byte) abort
  let found = ''
  for [start, end, layer, name, value] in get(a:packet, 'fields', [])
    if a:byte >= start && a:byte < end
      let found = printf('%s.%s = %s', layer, name, value)
    endif
  endfor
  if !empty(found)
    return found
  endif
  for [start, end, name] in get(a:packet, 'layers', [])
    if a:byte >= start && a:byte < end
      let found = name
    endif
  endfor
  return found
endfunction

function! s:describe_byte(lnum, byte) abort
  return s:describe_in(s:packet_meta(a:lnum), a:byte)
endfunction

" Public wrappers used by the agent bridge.
function! vimcap#describe_byte(lnum, byte) abort
  return s:describe_byte(a:lnum, a:byte)
endfunction

function! vimcap#detail_lines(bufnr, lnum, proto) abort
  return s:detail_lines(a:bufnr, a:lnum, a:proto)
endfunction

function! vimcap#statusline() abort
  let byte = s:cursor_byte()
  let packet = s:packet_meta(line('.'))
  let info = s:describe_in(packet, byte)
  let bad = get(packet, 'bad', [])
  let stale = get(b:, 'vimcap_stale', 0) ? '  [edited - :VimcapRefresh]' : ''
  return ' %f %m pkt %l/%L  byte ' . printf('0x%02X', byte)
        \ . (empty(info) ? '' : '  ' . substitute(info, '%', '%%', 'g'))
        \ . (empty(bad) ? '' : '  ✗' . join(bad, ' ✗') . ' (:VimcapFix)')
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
  call cursor(line('.'), s:hexcol(target))
endfunction

function! vimcap#goto_offset(offset) abort
  let byte = a:offset =~? '^0x' ? str2nr(a:offset[2:], 16) : str2nr(a:offset)
  call cursor(line('.'), s:hexcol(byte))
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
" Scapy-powered operations
" ---------------------------------------------------------------------------

" Send a request through the live daemon, or a one-shot 'rpc' subprocess
" when the daemon is unavailable (Neovim, or after a daemon failure).
" Reports errors itself and returns {} so callers can simply bail out.
function! vimcap#api(payload) abort
  let response = vimcap#live#request(a:payload)
  if empty(response)
    try
      let out = s:run('rpc', [json_encode(a:payload)])
      let response = empty(out) ? {} : json_decode(out[0])
    catch /^vimcap:/
      call s:error(v:exception)
      return {}
    endtry
  endif
  if has_key(response, 'error')
    call s:error('vimcap: ' . response.error)
    return {}
  endif
  return response
endfunction

function! s:base_payload() abort
  return {'linktype': s:linktype(), 'limit': vimcap#annotate_limit()}
endfunction

" Recompute checksums and length fields for the given packet lines.
function! vimcap#fix(line1, line2) abort
  let response = vimcap#api(extend(s:base_payload(),
        \ {'op': 'fix', 'packets': getline(a:line1, a:line2)}))
  if !has_key(response, 'packets')
    return
  endif
  let changed = 0
  for index in range(len(response.packets))
    if getline(a:line1 + index) !=# response.packets[index]
      call setline(a:line1 + index, response.packets[index])
      let changed += 1
    endif
  endfor
  call vimcap#live#flush(bufnr('%'))
  echo changed . ' packet' . (changed == 1 ? '' : 's') . ' fixed'
endfunction

" Set a protocol field by name on the current packet, e.g. 'IP.ttl=12'.
" Checksums and lengths are recomputed around the change.
function! vimcap#set_field(spec) abort
  let response = vimcap#api(extend(s:base_payload(),
        \ {'op': 'setfield', 'hex': getline('.'), 'spec': a:spec}))
  if has_key(response, 'hex')
    call setline('.', response.hex)
    call vimcap#live#flush(bufnr('%'))
  endif
endfunction

" Interactive field edit, prefilled with the field under the cursor.
function! vimcap#set_prompt() abort
  let field = matchstr(s:describe_byte(line('.'), s:cursor_byte()), '^[^ =]\+')
  let spec = input('set field: ', empty(field) ? '' : field . '=')
  redraw
  if !empty(spec)
    call vimcap#set_field(spec)
  endif
endfunction

" Append a packet built from a scapy expression below the cursor.
function! vimcap#craft(expr) abort
  let response = vimcap#api({'op': 'craft', 'expr': a:expr})
  if has_key(response, 'hex')
    call append(line('.'), response.hex)
    call vimcap#live#flush(bufnr('%'))
  endif
endfunction

" Yank the scapy expression that rebuilds the current packet.
function! vimcap#command_string() abort
  let response = vimcap#api(extend(s:base_payload(),
        \ {'op': 'command', 'hex': getline('.')}))
  if has_key(response, 'command')
    let @" = response.command
    silent! let @+ = response.command
    echo response.command
  endif
endfunction

" ---------------------------------------------------------------------------
" Filtering, streams, search, statistics
" ---------------------------------------------------------------------------

function! vimcap#foldexpr(lnum) abort
  return get(get(b:, 'vimcap_filter_match', {}), a:lnum, 0) ? 0 : 1
endfunction

function! vimcap#foldtext() abort
  return '  ' . (v:foldend - v:foldstart + 1) . ' packets filtered '
endfunction

function! s:apply_filter_folds(indices) abort
  let b:vimcap_filter_match = {}
  for index in a:indices
    let b:vimcap_filter_match[index] = 1
  endfor
  setlocal foldmethod=expr foldexpr=vimcap#foldexpr(v:lnum)
  setlocal foldtext=vimcap#foldtext() foldlevel=0 foldenable
endfunction

function! s:clear_filter() abort
  if exists('b:vimcap_filter_match')
    unlet b:vimcap_filter_match
  endif
  setlocal foldmethod=manual foldtext&
  normal! zE
endfunction

" Fold away packets not matching a layer name ('DNS') or Python expression
" ('p[TCP].dport == 80'). Bang or no argument clears the filter. Returns the
" matching indices, [] when cleared, or v:null when the expression failed.
function! vimcap#filter(bang, expr) abort
  if a:bang || empty(a:expr)
    call s:clear_filter()
    echo 'filter cleared'
    return []
  endif
  let response = vimcap#api(extend(s:base_payload(),
        \ {'op': 'filter', 'expr': a:expr, 'packets': getline(1, '$')}))
  if !has_key(response, 'indices')
    return v:null
  endif
  call s:apply_filter_folds(response.indices)
  echo len(response.indices) . '/' . line('$')
        \ . ' packets match (:VimcapFilter! clears)'
  return response.indices
endfunction

" Fold to the current packet's TCP/UDP conversation and show its payloads.
function! vimcap#follow() abort
  let response = vimcap#api(extend(s:base_payload(),
        \ {'op': 'follow', 'packets': getline(1, '$'), 'index': line('.')}))
  if !has_key(response, 'indices')
    return
  endif
  call s:apply_filter_folds(response.indices)
  call s:pane('vimcap://stream', response.lines, '')
  echo len(response.indices) . ' packets in conversation (:VimcapFilter! clears)'
endfunction

" Regex-search decoded payloads and load matches into the quickfix list.
function! vimcap#grep(pattern) abort
  let response = vimcap#api({'op': 'grep', 'pattern': a:pattern,
        \ 'packets': getline(1, '$')})
  if !has_key(response, 'matches')
    return
  endif
  let entries = map(copy(response.matches), {_, m -> {
        \ 'bufnr': bufnr('%'), 'lnum': m[0], 'col': s:hexcol(m[1]),
        \ 'text': printf('byte 0x%02X  %s', m[1], m[2])}})
  call setqflist(entries, 'r')
  if empty(entries)
    echo 'no matches'
  else
    copen
    wincmd p
  endif
endfunction

function! vimcap#stats() abort
  let response = vimcap#api(extend(s:base_payload(),
        \ {'op': 'stats', 'packets': getline(1, '$'),
        \  'times': vimcap#packet_times(bufnr('%'))}))
  if !has_key(response, 'lines')
    return
  endif
  call s:pane('vimcap://stats', response.lines, '')
  call s:apply_pane_syntax('stats', 'vimcap_stats_syntax', [
        \ 'syntax match VimcapHeader /^\d\+ packets .*/',
        \ 'syntax match VimcapLayerName /^\a.*/',
        \ 'syntax match VimcapBar /█\+/',
        \ 'syntax match VimcapBarTrack /░\+/'])
endfunction

" ---------------------------------------------------------------------------
" Anonymise, sniff, send, diff
" ---------------------------------------------------------------------------

" Consistently rewrite MAC and IP addresses (payload contents untouched).
function! vimcap#anonymise() abort
  let response = vimcap#api(extend(s:base_payload(),
        \ {'op': 'anon', 'packets': getline(1, '$')}))
  if has_key(response, 'packets')
    call setline(1, response.packets)
    call vimcap#live#flush(bufnr('%'))
    echo 'addresses anonymised (u undoes it)'
  endif
endfunction

" Capture packets from an interface and append them to the buffer.
" Needs capture privileges; the helper's error explains if they are missing.
function! vimcap#sniff(argstring) abort
  let parts = split(a:argstring)
  let iface = get(parts, 0, '')
  let packet_count = get(parts, 1, '10')
  if empty(iface) || packet_count !~# '^\d\+$'
    call s:error('vimcap: usage :VimcapSniff {iface} [count]')
    return
  endif
  let args = ['sniff', '--iface', iface, '--count', packet_count,
        \ '--timeout', string(get(g:, 'vimcap_sniff_timeout', 15))]

  " Vim with +job: stream packets into the buffer as they are captured. Other
  " runtimes (Neovim) fall back to a blocking capture that appears at the end.
  if !has('job')
    call s:sniff_blocking(args)
    return
  endif
  if exists('b:vimcap_sniff_job') && job_status(b:vimcap_sniff_job) ==# 'run'
    call s:error('vimcap: a sniff is already running (:VimcapSniffStop)')
    return
  endif
  let b:vimcap_sniff_count = 0
  let b:vimcap_sniff_job = job_start([s:python(), g:vimcap_script] + args, {
        \ 'out_mode': 'nl',
        \ 'out_cb': function('s:sniff_out', [bufnr('%')]),
        \ 'err_cb': function('s:sniff_err'),
        \ 'exit_cb': function('s:sniff_exit', [bufnr('%')])})
  echo 'sniffing ' . iface . '... (:VimcapSniffStop to end early)'
endfunction

function! s:sniff_out(bufnr, channel, line) abort
  call vimcap#sniff_feed(a:bufnr, a:line)
endfunction

" Append one captured packet line as it arrives, then debounce annotation so
" the colours/panes catch up without re-dissecting on every single packet.
" Public so the streaming path can be exercised without a live capture.
function! vimcap#sniff_feed(bufnr, line) abort
  if a:line !~? '^\s*\%(\x\x\s*\)\+$'
    return
  endif
  let hex = substitute(tolower(trim(a:line)), '\s\+', ' ', 'g')
  if getbufinfo(a:bufnr)[0].linecount == 1
        \ && empty(get(getbufline(a:bufnr, 1), 0, ''))
    call setbufline(a:bufnr, 1, hex)
  else
    call appendbufline(a:bufnr, '$', hex)
  endif
  call setbufvar(a:bufnr, 'vimcap_sniff_count',
        \ getbufvar(a:bufnr, 'vimcap_sniff_count', 0) + 1)
  call s:sniff_schedule(a:bufnr)
endfunction

function! s:sniff_err(channel, line) abort
  if a:line =~# 'vimcap:'
    call s:error(a:line)
  endif
endfunction

function! s:sniff_exit(bufnr, job, status) abort
  call s:sniff_annotate(a:bufnr)
  call setbufvar(a:bufnr, 'vimcap_sniff_job', v:null)
  let n = getbufvar(a:bufnr, 'vimcap_sniff_count', 0)
  echo n == 0 ? 'no packets captured' : (n . ' packets captured')
endfunction

" Debounced annotation of the packets streamed so far.
function! s:sniff_schedule(bufnr) abort
  let pending = getbufvar(a:bufnr, 'vimcap_sniff_timer', -1)
  if pending != -1
    call timer_stop(pending)
  endif
  call setbufvar(a:bufnr, 'vimcap_sniff_timer',
        \ timer_start(150, function('s:sniff_annotate_timer', [a:bufnr])))
endfunction

function! s:sniff_annotate_timer(bufnr, timer) abort
  call s:sniff_annotate(a:bufnr)
endfunction

" Re-dissect and lay out the workspace in the capture window's context, so
" window operations behave even though we are driven by an async callback.
function! s:sniff_annotate(bufnr) abort
  let winid = bufwinid(a:bufnr)
  if winid <= 0
    return
  endif
  call win_execute(winid,
        \ 'call vimcap#live#flush(' . a:bufnr . ') | call vimcap#open_workspace()')
  redraw
endfunction

function! vimcap#sniff_stop() abort
  if exists('b:vimcap_sniff_job') && type(b:vimcap_sniff_job) == v:t_job
        \ && job_status(b:vimcap_sniff_job) ==# 'run'
    call job_stop(b:vimcap_sniff_job)
    echo 'sniff stopped'
  else
    echo 'no sniff running'
  endif
endfunction

" Blocking capture for runtimes without +job: everything appears at the end.
function! s:sniff_blocking(args) abort
  echo 'sniffing ' . a:args[2] . '...'
  try
    let out = s:run(join(map(copy(a:args), 'shellescape(v:val)')), v:null)
  catch /^vimcap:/
    call s:error(v:exception)
    return
  endtry
  if empty(out)
    echo 'no packets captured'
    return
  endif
  if line('$') == 1 && empty(getline(1))
    call setline(1, out)
  else
    call append(line('$'), out)
  endif
  call vimcap#live#flush(bufnr('%'))
  call vimcap#open_workspace()
  echo len(out) . ' packets captured'
endfunction

" Transmit the given packets. Off by default: it puts traffic on the wire,
" so it must be enabled explicitly with g:vimcap_allow_send = 1.
function! vimcap#send(line1, line2, iface) abort
  if !get(g:, 'vimcap_allow_send', 0)
    call s:error('vimcap: transmitting is disabled; '
          \ . 'set g:vimcap_allow_send = 1 to enable :VimcapSend')
    return
  endif
  try
    let out = s:run('send --linktype ' . s:linktype()
          \ . (empty(a:iface) ? '' : ' --iface ' . shellescape(a:iface)),
          \ getline(a:line1, a:line2))
  catch /^vimcap:/
    call s:error(v:exception)
    return
  endtry
  echo get(out, 0, 'sent')
endfunction

" Compare this capture with another, vimdiff-style over the hex lines.
function! vimcap#diff(path) abort
  " Open the comparison capture quietly: no auto-panes and no agent terminal.
  let saved = [get(g:, 'vimcap_panes', v:null),
        \ get(g:, 'vimcap_auto_panes', v:null), get(g:, 'vimcap_auto_agent', v:null)]
  let g:vimcap_panes = []
  let g:vimcap_auto_panes = []
  let g:vimcap_auto_agent = 0
  try
    diffthis
    execute 'vertical split ' . fnameescape(a:path)
    diffthis
    wincmd p
  finally
    for [name, value] in [['vimcap_panes', saved[0]], ['vimcap_auto_panes', saved[1]],
          \ ['vimcap_auto_agent', saved[2]]]
      if value is v:null
        execute 'unlet! g:' . name
      else
        let g:[name] = value
      endif
    endfor
  endtry
endfunction

" ---------------------------------------------------------------------------
" Panes: ascii / utf8 / summary / detail
" ---------------------------------------------------------------------------

" Panes are grouped into regions and sized from configuration:
"
"   g:vimcap_panes     ordered list of the panes to open on load, e.g.
"                      ['detail', 'ascii', 'bits']. (g:vimcap_auto_panes is
"                      still honoured as the older name.)
"   g:vimcap_pane_region  {pane: 'right' | 'bottom'} overrides placement.
"                      'right' panes stack in a full-height column beside the
"                      hex; 'bottom' panes stack under it, column-aligned.
"   g:vimcap_pane_width   width (columns) of the right-hand column.
"   g:vimcap_pane_height  height (lines) of a bottom pane.
"   g:vimcap_pane_size    {pane: N} overrides one pane's cross-size (the
"                      height of a bottom or stacked-right pane).
"
" All names here are the short pane name ('detail'), not the buffer name
" ('vimcap://detail').

let s:default_region = {
      \ 'detail': 'right', 'summary': 'right',
      \ 'stream': 'right', 'stats': 'right', 'help': 'right',
      \ 'ascii': 'bottom', 'bits': 'bottom', 'utf8': 'bottom'}

" Panes to open automatically on load, in order. g:vimcap_panes is the
" current name; g:vimcap_auto_panes is kept as an alias. When neither is set,
" the welcome splash joins the defaults unless g:vimcap_welcome is off.
function! vimcap#auto_panes() abort
  if exists('g:vimcap_panes')
    return g:vimcap_panes
  endif
  if exists('g:vimcap_auto_panes')
    return g:vimcap_auto_panes
  endif
  let panes = ['detail', 'stats', 'ascii', 'bits']
  if get(g:, 'vimcap_welcome', 1)
    call add(panes, 'help')
  endif
  return panes
endfunction

" Builder for each pane by short name (all callable with no arguments).
let s:pane_builders = {
      \ 'detail': 'vimcap#detail', 'ascii': 'vimcap#ascii_pane',
      \ 'bits': 'vimcap#bits_pane', 'utf8': 'vimcap#utf8_pane',
      \ 'summary': 'vimcap#summary_pane', 'stats': 'vimcap#stats',
      \ 'help': 'vimcap#welcome'}

function! s:open_named_pane(pane) abort
  if has_key(s:pane_builders, a:pane)
    call call(s:pane_builders[a:pane], [])
  endif
endfunction

function! s:pane_name(buffer) abort
  return substitute(a:buffer, '^vimcap://', '', '')
endfunction

function! s:pane_region(buffer) abort
  let name = s:pane_name(a:buffer)
  return get(get(g:, 'vimcap_pane_region', {}), name,
        \ get(s:default_region, name, 'bottom'))
endfunction

" Width of the right-hand column (the column is shared, so this is per-column).
function! s:pane_width() abort
  return min([get(g:, 'vimcap_pane_width', 64), &columns / 2])
endfunction

" Height of a pane that is stacked (below the hex, or within a column). A
" per-pane g:vimcap_pane_size wins; the welcome splash defaults to its content
" height so it sits as a compact strip rather than taking half the column.
function! s:pane_height(name) abort
  let override = get(get(g:, 'vimcap_pane_size', {}), s:pane_name(a:name), 0)
  if override > 0
    return override
  endif
  if s:pane_name(a:name) ==# 'help'
    return min([len(s:welcome_lines()), &lines / 2])
  endif
  return min([get(g:, 'vimcap_pane_height', 10), &lines / 2])
endfunction

" An open pane window in the same region, to stack the new pane beneath.
" The open window at the given vertical end ('top' or 'bottom') of a region,
" or -1 when the region is empty. Picking by screen row (rather than trusting
" the unordered pane dict) means a new pane can always anchor to the real edge
" of the column.
function! s:region_window(region, ...) abort
  let want_top = a:0 > 0 && a:1 ==# 'top'
  let chosen = -1
  let chosen_row = -1
  for name in keys(s:default_region) + keys(get(g:, 'vimcap_pane_region', {}))
    let winid = s:pane_winid(name)
    if winid <= 0 || s:pane_region('vimcap://' . name) !=# a:region
      continue
    endif
    let row = win_screenpos(winid)[0]
    if chosen < 0 || (want_top ? row < chosen_row : row > chosen_row)
      let [chosen, chosen_row] = [winid, row]
    endif
  endfor
  return chosen
endfunction

" Open a window for a pane in its configured region, sized from config.
" hex_win anchors 'bottom' panes so they stay under the hex, not full width.
function! s:open_pane_window(name, existing, hex_win) abort
  let region = s:pane_region(a:name)
  " The welcome splash anchors to the top of its column; everything else
  " appends beneath the bottom pane, so each stacks in the order it opened.
  let is_help = s:pane_name(a:name) ==# 'help'
  let neighbour = s:region_window(region, is_help ? 'top' : 'bottom')
  let open = a:existing > 0 ? ('sbuffer ' . a:existing) : 'new'

  if neighbour > 0
    " Stack within the region. Stacked panes are sized by height (the column
    " width is already fixed by the first pane).
    call win_gotoid(neighbour)
    execute (is_help ? 'aboveleft ' : 'belowright ') . open
    execute 'resize' s:pane_height(a:name)
  elseif region ==# 'right'
    execute 'botright vertical ' . open
    execute 'vertical resize' s:pane_width()
    setlocal winfixwidth
  else
    " First bottom pane: split the hex window so it sits under it.
    if a:hex_win > 0
      call win_gotoid(a:hex_win)
    endif
    execute 'belowright ' . open
    execute 'resize' s:pane_height(a:name)
    setlocal winfixheight
  endif

  if a:existing < 0
    setlocal buftype=nofile bufhidden=wipe noswapfile
    silent! execute 'file ' . fnameescape(a:name)
    " q dismisses the whole workspace from within any pane; Tab maximises /
    " restores the focused pane.
    nnoremap <buffer> <silent> q :call vimcap#close_panes()<CR>
    nnoremap <buffer> <silent> <Tab> :call vimcap#zoom()<CR>
    " Moving the cursor here drives the hex view and every other pane.
    execute 'autocmd CursorMoved <buffer> call vimcap#pane_cursor_moved('
          \ . string(s:pane_name(a:name)) . ')'
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
    call s:open_pane_window(a:name, existing, source_win)
  endif
  setlocal modifiable
  silent keepjumps %delete _
  call setline(1, a:lines)
  setlocal nomodifiable nowrap
  if a:bind ==# 'cursor'
    setlocal cursorbind scrollbind cursorline
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

" Precompute each byte value's rendering once, so building a line is just a
" table lookup per byte rather than a per-bit loop.
" Both bit glyphs are 3 bytes (█ U+2588, ░ U+2591) so every byte occupies a
" fixed byte-width in the line — this lets the cursor highlight use matchaddpos
" (O(1)) instead of a \%v regex, which is O(n^2) on very long packet rows.
let s:ascii_glyph = []
let s:bits_glyph = []
for s:b in range(256)
  call add(s:ascii_glyph, (s:b >= 32 && s:b < 127) ? nr2char(s:b) : '.')
  let s:g = ''
  for s:w in [128, 64, 32, 16, 8, 4, 2, 1]
    let s:g .= and(s:b, s:w) ? '█' : '░'
  endfor
  call add(s:bits_glyph, s:g)
endfor
unlet s:b s:w s:g

function! s:ascii_line(hexline) abort
  return join(map(split(a:hexline), 's:ascii_glyph[str2nr(v:val, 16)]'), '  ')
endfunction

function! s:bits_line(hexline) abort
  return join(map(split(a:hexline), 's:bits_glyph[str2nr(v:val, 16)]'), ' ')
endfunction

" Byte-aligned panes rendered from the hex bytes. Per byte N (0-based):
"   cols   screen columns per byte (for the reverse cursor mapping)
"   bytecol  1-based byte offset of the byte in the rendered line (N*stride+1)
"   bytelen  byte length to highlight for one byte
" ascii: "X  " = 3 bytes/byte, highlight 1. bits: 8*3-byte glyphs + space = 25
" bytes/byte, highlight the 24-byte group.
let s:byte_panes = {
      \ 'ascii': {'line': function('s:ascii_line'), 'cols': 3, 'stride': 3, 'bytelen': 1},
      \ 'bits':  {'line': function('s:bits_line'),  'cols': 9, 'stride': 25, 'bytelen': 24}}

function! s:byte_pane_lines(bufnr, Formatter) abort
  return map(getbufline(a:bufnr, 1, '$'), {_, line -> a:Formatter(line)})
endfunction

function! s:summary_lines(bufnr) abort
  let packets = s:packets(a:bufnr)
  return map(copy(packets),
        \ {index, packet -> printf('%4d  %s', index + 1, get(packet, 's', ''))})
endfunction

function! vimcap#ascii_pane() abort
  call s:pane('vimcap://ascii',
        \ s:byte_pane_lines(bufnr('%'), s:byte_panes.ascii.line), 'scroll')
endfunction

function! vimcap#utf8_pane() abort
  call s:filter_pane('vimcap://utf8', 'utf8', 'scroll')
endfunction

function! vimcap#bits_pane() abort
  call s:pane('vimcap://bits',
        \ s:byte_pane_lines(bufnr('%'), s:byte_panes.bits.line), 'scroll')
  call s:apply_pane_syntax('bits', 'vimcap_bits_syntax', [
        \ 'syntax match VimcapBitOn /█\+/',
        \ 'syntax match VimcapBitOff /░\+/'])
endfunction

" Re-render the detail pane (one packet, under the hex cursor) if it is open.
function! s:refresh_detail_pane(bufnr) abort
  let hexwin = bufwinid(a:bufnr)
  if hexwin > 0 && s:pane_winid('detail') > 0
    call s:sync_pane('vimcap://detail', s:detail_lines(a:bufnr,
          \ line('.', hexwin), getbufvar(a:bufnr, 'vimcap_detail_proto', '')))
  endif
endfunction

" Rebuild only the given 1-based lines in the open byte/summary panes. Used on
" live edits so a one-line change costs one line of work, not a full rebuild.
function! vimcap#update_pane_lines(bufnr, lines) abort
  if empty(a:lines)
    return
  endif
  for [name, spec] in items(s:byte_panes)
    if s:pane_winid(name) < 0
      continue
    endif
    let pane = bufnr('vimcap://' . name)
    call setbufvar(pane, '&modifiable', 1)
    for lnum in a:lines
      call setbufline(pane, lnum, spec.line(get(getbufline(a:bufnr, lnum), 0, '')))
    endfor
    call setbufvar(pane, '&modifiable', 0)
  endfor
  if s:pane_winid('summary') >= 0
    let summary = bufnr('vimcap://summary')
    let packets = s:packets(a:bufnr)
    call setbufvar(summary, '&modifiable', 1)
    for lnum in a:lines
      if lnum <= len(packets)
        call setbufline(summary, lnum,
              \ printf('%4d  %s', lnum, get(packets[lnum - 1], 's', '')))
      endif
    endfor
    call setbufvar(summary, '&modifiable', 0)
  endif
  " The detail pane shows one packet; refresh it only if that packet changed.
  let hexwin = bufwinid(a:bufnr)
  if hexwin > 0 && index(a:lines, line('.', hexwin)) >= 0
    call s:refresh_detail_pane(a:bufnr)
  endif
endfunction

" Bring every open pane in line with the buffer's current bytes and
" annotations. Called after structural edits and :VimcapRefresh. Lines are only
" built for panes that are actually open, so closed panes cost nothing.
function! vimcap#update_panes(bufnr) abort
  for [name, spec] in items(s:byte_panes)
    if s:pane_winid(name) >= 0
      call s:sync_pane('vimcap://' . name,
            \ s:byte_pane_lines(a:bufnr, spec.line))
    endif
  endfor
  if s:pane_winid('summary') >= 0
    call s:sync_pane('vimcap://summary', s:summary_lines(a:bufnr))
  endif
  call s:refresh_detail_pane(a:bufnr)
endfunction

function! vimcap#summary_pane(...) abort
  let proto = a:0 && !empty(a:1) ? a:1 : ''
  let packets = s:packets(bufnr('%'))
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
" A styled dissection view for packet a:lnum, built from the annotations we
" already have (layers + per-field offsets + values + checksum flags). Returns
" [lines, fieldmap] where fieldmap is [[start_byte, end_byte, line], ...] for
" cursor-field emphasis. Returns [[], []] when there is nothing to render, so
" the caller can fall back to scapy's show().
function! s:detail_from_meta(bufnr, lnum) abort
  let packets = s:packets(a:bufnr)
  if a:lnum > len(packets)
    return [[], []]
  endif
  let p = packets[a:lnum - 1]
  if empty(get(p, 'layers', []))
    return [[], []]
  endif
  let path = join(map(copy(p.layers), 'v:val[2]'), ' › ')
  let header = printf('Packet %d/%d   %s   %d bytes',
        \ a:lnum, len(packets), get(p, 't', ''), get(p, 'wl', 0))
  let lines = [header, path, repeat('─', max([strchars(path), 44]))]
  let bad = get(p, 'bad', [])
  let fieldmap = []
  for [lstart, lend, lname] in p.layers
    call add(lines, printf('▸ %s  ·  %d B', lname, lend - lstart))
    for [fstart, fend, flayer, fname, fvalue] in get(p, 'fields', [])
      if flayer !=# lname || fstart < lstart || fstart >= lend
        continue
      endif
      let flag = index(bad, flayer . '.' . fname) >= 0 ? '  ✗' : ''
      call add(lines, printf('    0x%02X  %-9s %s%s', fstart, fname, fvalue, flag))
      call add(fieldmap, [fstart, fend, len(lines)])
    endfor
  endfor
  return [lines, fieldmap]
endfunction

function! s:detail_lines(bufnr, lnum, proto) abort
  " Prefer the rich, offset-annotated view; it needs no subprocess and works
  " without the live daemon. A specific --proto forces scapy's own show().
  let s:detail_packet_lnum = a:lnum
  " The field rows just changed, so invalidate the highlight-row cache.
  let s:detail_field_line = -1
  if empty(a:proto)
    let [lines, fieldmap] = s:detail_from_meta(a:bufnr, a:lnum)
    if !empty(lines)
      let s:detail_fieldmap = fieldmap
      return lines
    endif
  endif
  let s:detail_fieldmap = []
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

" Colour the detail buffer. Patterns cover both the rich view (header / ▸
" headings / offsets) and the scapy-show fallback (###[ Layer ]###). Set once
" per detail buffer (it is wiped and recreated, so the flag resets with it).
function! s:detail_apply_syntax() abort
  call s:apply_pane_syntax('detail', 'vimcap_detail_syntax', [
        \ 'syntax match VimcapHeader /^Packet .*/',
        \ 'syntax match VimcapRule /^─\+$/',
        \ 'syntax match VimcapLayerName /^▸ .*/',
        \ 'syntax match VimcapLayerName /^###\[ .* \]###/',
        \ 'syntax match VimcapPathSep /›/',
        \ 'syntax match VimcapOffset /^\s\+\zs0x\x\+/',
        \ 'syntax match VimcapVendor /(\a[^)]*)$/',
        \ 'syntax match VimcapBad /✗/'])
endfunction

" Emphasise the detail row for the field under the cursor, and scroll to it.
function! s:detail_highlight_field() abort
  let winid = s:pane_winid('detail')
  if winid <= 0
    return
  endif
  let byte = s:cursor_byte()
  let target = 0
  for [start, end, idx] in get(s:, 'detail_fieldmap', [])
    if byte >= start && byte < end
      let target = idx
      break
    endif
  endfor
  " Skip the win_execute (and detail-pane redraw) when the highlighted field
  " row has not changed — i.e. the cursor is still within the same field.
  if target == get(s:, 'detail_field_line', -1)
    return
  endif
  let s:detail_field_line = target
  call win_execute(winid, [
        \ 'if exists("w:vimcap_field_match") | silent! call matchdelete(w:vimcap_field_match) | endif',
        \ 'let w:vimcap_field_match = ' . (target > 0
        \     ? 'matchaddpos("VimcapFieldCursor", [' . target . '])' : '-1'),
        \ target > 0 ? 'call cursor(' . target . ', 1)' : ''])
endfunction

function! vimcap#detail(...) abort
  let b:vimcap_detail_proto = a:0 && !empty(a:1) ? a:1 : ''
  let b:vimcap_detail_lnum = line('.')
  call s:pane('vimcap://detail',
        \ s:detail_lines(bufnr('%'), line('.'), b:vimcap_detail_proto), '')
  call s:detail_apply_syntax()
  call s:detail_highlight_field()
endfunction

" The welcome splash: an ASCII cap logo (🧢) and a quick command reference.
function! s:welcome_lines() abort
  return [
        \ '',
        \ '   🧢  vimcap',
        \ '       a pcap hex editor',
        \ '',
        \ '  Getting started',
        \ '    :VimcapSniff en0     capture live from an interface',
        \ '    K                    toggle the dissection pane',
        \ '    >a  >b  >s           ascii · binary · summary panes',
        \ '    w   b                jump between protocol fields',
        \ '    >f                   edit the field under the cursor',
        \ '    :VimcapFix           recompute checksums',
        \ '    :VimcapFilter dns    fold to matching packets',
        \ '    :VimcapTheme neon    switch the colour theme',
        \ '    :VimcapAgent         ask an AI agent for help',
        \ '    Q                    close all panes',
        \ '',
        \ '  :help vimcap   ·   :VimcapHealth',
        \ '']
endfunction

function! vimcap#welcome() abort
  call s:pane('vimcap://help', s:welcome_lines(), '')
  call s:apply_pane_syntax('help', 'vimcap_help_syntax', [
        \ 'syntax match VimcapHeader /vimcap/',
        \ 'syntax match VimcapPath /a pcap hex editor/',
        \ 'syntax match VimcapLayerName /^  \u.*/',
        \ 'syntax match VimcapValue /:\a\+/',
        \ 'syntax match VimcapField /^\s\+\zs[A-Z>][a-z>]*\ze\s\{2}/'])
endfunction

function! vimcap#welcome_toggle() abort
  call s:toggle_pane('help', function('vimcap#welcome'))
endfunction

" Close every vimcap pane (and the agent terminal), leaving just the hex.
let s:all_panes = ['detail', 'summary', 'stream', 'stats', 'ascii', 'bits',
      \ 'utf8', 'help']

function! vimcap#close_panes() abort
  let closed = 0
  for name in s:all_panes
    let winid = s:pane_winid(name)
    if winid > 0
      call win_execute(winid, 'close')
      let closed += 1
    endif
  endfor
  if exists('*vimcap#agent#active') && vimcap#agent#active()
    call vimcap#agent#stop()
    let closed += 1
  endif
  echo closed > 0 ? 'panes closed' : 'no panes open'
endfunction

" The capture (hex) buffer for the current layout: the window on screen whose
" buffer is a vimcap capture (not a vimcap:// pane).
function! s:find_hex_buf() abort
  if &filetype ==# 'vimcap' && bufname('%') !~# '^vimcap://'
    return bufnr('%')
  endif
  for nr in range(1, winnr('$'))
    let buf = winbufnr(nr)
    if getbufvar(buf, '&filetype') ==# 'vimcap' && bufname(buf) !~# '^vimcap://'
      return buf
    endif
  endfor
  return bufnr('%')
endfunction

" Close every window except the focused one and the right-hand sidebar panes
" (detail, welcome, ...), so the focused view grows but the reference sidebar
" stays. Returns how many windows were closed.
function! s:zoom_keep_sidebar() abort
  let keep = win_getid()
  let closed = 0
  for nr in reverse(range(1, winnr('$')))
    let wid = win_getid(nr)
    if wid == keep
      continue
    endif
    let name = bufname(winbufnr(nr))
    if name =~# '^vimcap://' && s:pane_region(name) ==# 'right'
      continue
    endif
    call win_execute(wid, 'close')
    let closed += 1
  endfor
  return closed
endfunction

" Zoom cycle, toggled with <Tab>:
"   normal -> maximise the focused view but keep the right sidebar
"          -> full screen (focused view only)
"          -> back to the full layout
function! vimcap#zoom() abort
  let state = get(t:, 'vimcap_zoom', 0)
  let save_hidden = &hidden
  set hidden
  if state == 0
    let t:vimcap_zoom_hex = s:find_hex_buf()
    let closed = s:zoom_keep_sidebar()
    " Nothing but the sidebar to hide? Jump straight to full screen.
    let t:vimcap_zoom = closed > 0 ? 1 : 2
    if t:vimcap_zoom == 2
      only
    endif
  elseif state == 1
    only
    let t:vimcap_zoom = 2
  else
    let t:vimcap_zoom = 0
    let hex = get(t:, 'vimcap_zoom_hex', s:find_hex_buf())
    if bufexists(hex) && bufnr('%') != hex
      execute 'buffer' hex
    endif
    call vimcap#open_workspace()
  endif
  let &hidden = save_hidden
endfunction

" K: show the dissection pane, or put it away if it is already showing.
function! vimcap#detail_toggle() abort
  call s:toggle_pane('detail', function('vimcap#detail'))
endfunction

" Cursor sync is kept loop-free without locks or timers: s:last_track records
" the [line, byte] the views were last synced to. Both handlers no-op when the
" cursor is already there, so the programmatic moves they make (which re-fire
" CursorMoved) converge immediately instead of cascading.
let s:linked_panes = {'ascii': 1, 'bits': 1, 'utf8': 1, 'summary': 1, 'detail': 1}

" Point every open view at the byte under the hex cursor: byte-aligned panes
" at their own columns-per-byte, summary/UTF-8 at the packet line, detail at
" the field.
function! s:do_track() abort
  let lnum = line('.')
  let byte = s:cursor_byte()
  let s:last_track = [lnum, byte]
  " Record which capture these shared panes now reflect, so the reverse link
  " drives this buffer (not whichever hex window s:find_hex_buf happens upon)
  " when several captures are open at once.
  let s:sync_src = bufnr('%')
  call s:highlight_cursor_byte(lnum, byte)
  for [name, spec] in items(s:byte_panes)
    call s:track_pane('vimcap://' . name, lnum, byte * spec.stride + 1, spec.bytelen)
  endfor
  call s:track_pane('vimcap://summary', lnum, -1, 0)
  call s:track_pane('vimcap://utf8', lnum, -1, 0)
  call vimcap#detail_follow()
  call s:detail_highlight_field()
endfunction

" Hex CursorMoved handler.
function! vimcap#track_cursor() abort
  if [line('.'), s:cursor_byte()] == get(s:, 'last_track', [])
    return
  endif
  call s:do_track()
endfunction

" Reverse link: a cursor move inside a byte/packet-aligned pane drives the hex
" view (and thus every other pane) back to the matching byte/packet.
function! vimcap#pane_cursor_moved(name) abort
  if !has_key(s:linked_panes, a:name)
    return
  endif
  let hexline = line('.')
  let byte = 0
  if has_key(s:byte_panes, a:name)
    " Inverse of s:do_track's forward mapping, using the same cols constant.
    let byte = (virtcol('.') - 1) / s:byte_panes[a:name].cols
  elseif a:name ==# 'detail'
    let hexline = get(s:, 'detail_packet_lnum', hexline)
    for [start, end, idx] in get(s:, 'detail_fieldmap', [])
      if idx == line('.')
        let byte = start
        break
      endif
    endfor
  endif
  " summary / utf8: one line per packet, so the line maps straight across.
  " No-op when the hex is already here — this move came from our own tracking.
  if [hexline, byte] == get(s:, 'last_track', [])
    return
  endif
  " Drive the capture these panes currently reflect; fall back to a scan.
  let src = get(s:, 'sync_src', 0)
  let hexwin = src > 0 ? bufwinid(src) : -1
  if hexwin <= 0
    let hexwin = bufwinid(s:find_hex_buf())
  endif
  if hexwin <= 0
    return
  endif
  " track_cursor's guard is false here (the position just changed), so it runs.
  call win_execute(hexwin,
        \ 'call cursor(' . hexline . ', ' . s:hexcol(byte) . ') | call vimcap#track_cursor()')
endfunction

" Point a pane's cursor at byte-column bytecol on line lnum. When bytelen > 0,
" highlight bytelen bytes there with matchaddpos (O(1), unlike a \%v regex which
" is pathological on long rows). bytecol <= 0 means "line only" (summary/utf8).
function! s:track_pane(name, lnum, bytecol, bytelen) abort
  let winid = bufwinid(bufnr(a:name))
  if winid < 0
    return
  endif
  let col = a:bytecol > 0 ? a:bytecol : 1
  let commands = ['call cursor(' . a:lnum . ', ' . col . ')']
  if a:bytelen > 0
    call add(commands, 'if get(w:, "vimcap_track", -1) != -1'
          \ . ' | silent! call matchdelete(w:vimcap_track) | endif')
    call add(commands, 'let w:vimcap_track = matchaddpos("VimcapCursorByte", [['
          \ . a:lnum . ', ' . a:bytecol . ', ' . a:bytelen . ']])')
  endif
  call win_execute(winid, commands)
endfunction

" While the detail pane is open, keep it on the packet under the cursor.
" The rich view renders from annotations (cheap); only the scapy-show
" fallback is costly, so skip following when we have neither.
function! vimcap#detail_follow() abort
  if s:pane_winid('detail') <= 0
        \ || get(b:, 'vimcap_detail_lnum', -1) == line('.')
    return
  endif
  let packets = s:packets(bufnr('%'))
  let has_meta = line('.') <= len(packets)
        \ && !empty(get(get(packets, line('.') - 1, {}), 'layers', []))
  if !has_meta && !vimcap#live#available()
    return
  endif
  let b:vimcap_detail_lnum = line('.')
  call s:sync_pane('vimcap://detail', s:detail_lines(bufnr('%'), line('.'),
        \ get(b:, 'vimcap_detail_proto', '')))
  call s:detail_apply_syntax()
  " s:do_track (the only caller) highlights the field itself right after.
endfunction
