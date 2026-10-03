" Live dissection: re-annotate packets automatically as the buffer changes.
"
" Edits are debounced with a timer; when it fires, changed lines are sent to
" a persistent helper daemon ('vimcap.py serve') over a channel, so updates
" cost milliseconds instead of a scapy import per keystroke. Structural
" changes (packets added or removed) trigger a full re-annotation. Neovim
" has no ch_evalraw, so it falls back to a debounced subprocess refresh.

let s:disabled = 0

function! s:enabled() abort
  return !s:disabled && get(g:, 'vimcap_live', 1)
endfunction

" Called from the TextChanged autocmds in the capture buffer.
function! vimcap#live#on_change() abort
  let b:vimcap_stale = 1
  if !s:enabled()
    return
  endif
  if get(b:, 'vimcap_live_timer', -1) != -1
    call timer_stop(b:vimcap_live_timer)
  endif
  let b:vimcap_live_timer = timer_start(get(g:, 'vimcap_live_delay', 300),
        \ function('s:fire', [bufnr('%')]))
endfunction

function! s:fire(bufnr, timer) abort
  call vimcap#live#flush(a:bufnr)
endfunction

" Start the daemon ahead of the first edit so the scapy import has already
" happened by the time an annotation is needed.
function! vimcap#live#warm() abort
  if !s:enabled() || has('nvim')
    return
  endif
  try
    call s:daemon()
  catch
  endtry
endfunction

" Re-annotate whatever has changed since the last annotation. Public so it
" can be invoked synchronously (used by the tests).
function! vimcap#live#flush(bufnr) abort
  let pending = getbufvar(a:bufnr, 'vimcap_live_timer', -1)
  if pending != -1
    call timer_stop(pending)
    call setbufvar(a:bufnr, 'vimcap_live_timer', -1)
  endif
  let meta = getbufvar(a:bufnr, 'vimcap', {})
  if empty(meta) || !s:enabled()
    return
  endif
  let cached = getbufvar(a:bufnr, 'vimcap_lines', [])
  let current = getbufline(a:bufnr, 1, '$')
  if current ==# cached
    call s:mark_fresh(a:bufnr, current)
    return
  endif

  if has('nvim')
    " Debounced full refresh through the ordinary subprocess path.
    let winid = bufwinid(a:bufnr)
    if winid > 0
      call win_execute(winid, 'call vimcap#refresh()')
    endif
    return
  endif

  let limit = vimcap#annotate_limit()
  let linktype = vimcap#linktype(a:bufnr)
  let packets = get(meta, 'packets', [])

  let changed = []
  if len(current) == len(cached) && len(current) == len(packets)
    let result = s:update_changed_lines(a:bufnr, current, cached, packets, linktype, limit)
    let [updated, changed] = [result.ok, result.lines]
  elseif len(current) <= limit
    let updated = s:update_all_lines(a:bufnr, meta, current, linktype, limit)
  else
    " Too large to re-annotate on the fly; leave it to :VimcapRefresh / :w.
    return
  endif
  if !s:disabled
    " A line that failed to dissect (e.g. half-typed hex) stays stale, so
    " the statusline keeps saying so and the next flush retries it.
    if updated
      call s:mark_fresh(a:bufnr, current)
    endif
    " In-place edits refresh only their own lines; structural edits rebuild.
    if !empty(changed)
      call vimcap#update_pane_lines(a:bufnr, changed)
    else
      call vimcap#update_panes(a:bufnr)
    endif
  endif
endfunction

" True when annotation requests can be answered by the daemon.
function! vimcap#live#available() abort
  return !has('nvim') && s:enabled()
endfunction

" Dissection tree for a single packet, served by the daemon.
" Returns [] on any failure so callers can fall back to a subprocess.
function! vimcap#live#show(linktype, hex, proto) abort
  let response = s:request({'op': 'show', 'linktype': a:linktype,
        \ 'hex': a:hex, 'proto': a:proto})
  return get(response, 'lines', [])
endfunction

" Send an arbitrary request through the daemon; {} when it is unavailable,
" so callers can fall back to a one-shot subprocess.
function! vimcap#live#request(payload) abort
  if !vimcap#live#available()
    return {}
  endif
  return s:request(a:payload)
endfunction

function! s:mark_fresh(bufnr, lines) abort
  call setbufvar(a:bufnr, 'vimcap_lines', a:lines)
  call setbufvar(a:bufnr, 'vimcap_stale', 0)
  redrawstatus
endfunction

" Same packet count: re-dissect only the edited lines. Returns {ok, lines}
" where lines are the 1-based line numbers that changed (for incremental pane
" refresh) and ok is false if any changed line failed to dissect.
function! s:update_changed_lines(bufnr, current, cached, packets, linktype, limit) abort
  let all_updated = 1
  let changed = []
  for index in range(len(a:current))
    if a:current[index] ==# a:cached[index] || index >= a:limit
      continue
    endif
    call add(changed, index + 1)
    let entry = a:packets[index]
    let response = s:request({
          \ 'op': 'packet',
          \ 'hex': a:current[index],
          \ 'linktype': a:linktype,
          \ 't': get(entry, 't', '0'),
          \ 'wl': get(entry, 'wl', 0)})
    if has_key(response, 'packet')
      let a:packets[index] = response.packet
      call vimcap#highlight_line(a:bufnr, index + 1)
    else
      let all_updated = 0
    endif
  endfor
  return {'ok': all_updated, 'lines': changed}
endfunction

" Packets were added or removed: re-annotate everything, and keep the sidecar
" in sync so :w still writes the right timestamps. Timestamps map to packets
" by position, which only holds for the unchanged prefix — past the first
" changed line we cannot know which old packet a line corresponds to, so we
" stop carrying exact times there (the helper carries the last known one
" forward) rather than shuffling an unrelated packet's timestamp onto it.
function! s:update_all_lines(bufnr, meta, current, linktype, limit) abort
  let cached = getbufvar(a:bufnr, 'vimcap_lines', [])
  let prefix = 0
  while prefix < len(a:current) && prefix < len(cached)
        \ && a:current[prefix] ==# cached[prefix]
    let prefix += 1
  endwhile
  let times = prefix > 0 ? vimcap#packet_times(a:bufnr)[: prefix - 1] : []
  let wirelens = prefix > 0 ? vimcap#packet_wirelens(a:bufnr)[: prefix - 1] : []
  let response = s:request({
        \ 'op': 'annotate',
        \ 'linktype': a:linktype,
        \ 'limit': a:limit,
        \ 'packets': a:current,
        \ 'times': times,
        \ 'wirelens': wirelens})
  if !has_key(response, 'packets')
    return 0
  endif
  let a:meta.packets = response.packets
  call setbufvar(a:bufnr, 'vimcap', a:meta)
  call vimcap#apply_highlights(a:bufnr)
  let metafile = getbufvar(a:bufnr, 'vimcap_meta_file', '')
  if !empty(metafile)
    call writefile([json_encode(a:meta)], metafile)
  endif
  return 1
endfunction

" ---------------------------------------------------------------------------
" Daemon plumbing (Vim only)
" ---------------------------------------------------------------------------

function! s:daemon() abort
  if exists('s:job') && job_status(s:job) ==# 'run'
    return s:job
  endif
  let s:job = job_start(
        \ [get(g:, 'vimcap_python', 'python3'), g:vimcap_script, 'serve'],
        \ {'mode': 'nl'})
  return s:job
endfunction

function! s:request(payload) abort
  try
    let channel = job_getchannel(s:daemon())
    let response = ch_evalraw(channel, json_encode(a:payload) . "\n",
          \ {'timeout': get(g:, 'vimcap_live_timeout', 3000)})
  catch
    call s:disable()
    return {}
  endtry
  if empty(response)
    call s:disable()
    return {}
  endif
  try
    return json_decode(response)
  catch
    return {}
  endtry
endfunction

function! s:disable() abort
  let s:disabled = 1
  echohl WarningMsg
  echomsg 'vimcap: live dissection disabled (helper unavailable); '
        \ . 'use :VimcapRefresh instead'
  echohl None
endfunction
