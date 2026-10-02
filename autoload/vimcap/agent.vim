" Agentic mode: let an AI agent (Claude Code by default) drive the vimcap
" session. :VimcapAgent opens the agent in a terminal split and hands it a
" structured toolset over an MCP bridge (python/vimcap.py mcp): the agent's
" tool calls arrive here as vimcap#agent#dispatch() invocations over a Vim
" JSON channel, so it can inspect, navigate and edit the capture while the
" user watches every change live.
"
" Trust model: the bridge listens on 127.0.0.1 with a per-session token, and
" the agent only reaches the operations dispatch() implements. Raw ex
" commands stay off unless g:vimcap_agent_raw is set.

let s:bufnr = -1
let s:channel = v:null
let s:term_buf = -1
let s:session_file = ''
let s:poll_timer = -1
let s:user_stopped = 0

function! vimcap#agent#active() abort
  return s:term_buf > 0 && bufexists(s:term_buf)
endfunction

" Called on capture load when g:vimcap_auto_agent is set: start the agent
" if this is an interactive session with the agent CLI available, and the
" user has not dismissed it (:VimcapAgent! wins for the rest of the session).
function! vimcap#agent#auto() abort
  if s:user_stopped || vimcap#agent#active()
        \ || has('nvim') || !has('terminal') || !has('channel')
        \ || !has('ttyin') || !has('ttyout')
        \ || !executable(get(g:, 'vimcap_agent_cmd', 'claude'))
    return
  endif
  " Defer the launch: starting a terminal split mid-BufReadCmd leaves the
  " window layout unsettled, so schedule it once load has finished.
  let s:auto_hex_win = bufwinid(bufnr('%'))
  call timer_start(0, function('s:auto_launch'))
endfunction

function! s:auto_launch(timer) abort
  if vimcap#agent#active() || s:user_stopped
    return
  endif
  call vimcap#agent#start(0, '')
  if s:auto_hex_win > 0 && win_id2win(s:auto_hex_win) > 0
    call win_gotoid(s:auto_hex_win)
  endif
endfunction

function! vimcap#agent#start(bang, prompt) abort
  if a:bang
    let s:user_stopped = 1
    call vimcap#agent#stop()
    return
  endif
  let s:user_stopped = 0
  if has('nvim') || !has('terminal') || !has('channel')
    echohl ErrorMsg
    echomsg 'vimcap: agent mode needs Vim with +terminal and +channel'
    echohl None
    return
  endif
  let agent_cmd = get(g:, 'vimcap_agent_cmd', 'claude')
  if !executable(agent_cmd)
    echohl ErrorMsg
    echomsg 'vimcap: ' . agent_cmd . ' is not executable; '
          \ . 'set g:vimcap_agent_cmd or install Claude Code'
    echohl None
    return
  endif
  call vimcap#agent#stop()

  let s:bufnr = bufnr('%')
  let s:session_file = tempname() . '.vimcap-agent.json'
  let mcp_config = tempname() . '.vimcap-mcp.json'
  call writefile([json_encode({'mcpServers': {'vimcap': {
        \ 'command': get(g:, 'vimcap_python', 'python3'),
        \ 'args': [g:vimcap_script, 'mcp', '--session', s:session_file]}}})],
        \ mcp_config)

  let task = empty(a:prompt)
        \ ? 'Give me an overview of this capture and point out anything odd.'
        \ : a:prompt
  let briefing = 'You are working inside vimcap, a Vim hex editor for packet'
        \ . ' captures, and control the live session through the mcp__vimcap'
        \ . ' tools. The user is watching: every edit appears immediately,'
        \ . ' and vimcap_goto moves their cursor, so navigate to whatever you'
        \ . ' discuss. Start with vimcap_overview. Task: ' . task

  let command = [agent_cmd, '--mcp-config', mcp_config,
        \ '--allowedTools', 'mcp__vimcap__*', briefing]
  " The agent terminal opens where g:vimcap_agent_position says ('right' by
  " default, else 'left' or 'bottom'), sized from config, without disturbing
  " the hex/pane layout.
  let position = get(g:, 'vimcap_agent_position', 'right')
  let opener = position ==# 'bottom' ? 'botright'
        \ : position ==# 'left' ? 'topleft vertical' : 'botright vertical'
  execute opener . ' new'
  let s:term_buf = term_start(command, {
        \ 'term_name': 'vimcap://agent',
        \ 'term_finish': 'close',
        \ 'curwin': 1})
  if position ==# 'bottom'
    execute 'resize' get(g:, 'vimcap_agent_height', 15)
  else
    execute 'vertical resize' get(g:, 'vimcap_agent_width', 80)
  endif
  let s:poll_timer = timer_start(500, function('s:try_connect'), {'repeat': 60})
endfunction

function! vimcap#agent#stop() abort
  if s:poll_timer != -1
    call timer_stop(s:poll_timer)
    let s:poll_timer = -1
  endif
  if s:channel isnot v:null
    silent! call ch_close(s:channel)
    let s:channel = v:null
  endif
  if s:term_buf > 0 && bufexists(s:term_buf)
    silent! execute 'bwipeout!' s:term_buf
  endif
  let s:term_buf = -1
  if !empty(s:session_file)
    call delete(s:session_file)
    let s:session_file = ''
  endif
endfunction

" Poll the session file until the MCP bridge has published its port, then
" connect and authenticate. The bridge drives us from there.
function! s:try_connect(timer) abort
  if !filereadable(s:session_file)
    return
  endif
  try
    let session = json_decode(join(readfile(s:session_file), ''))
  catch
    return
  endtry
  if type(session) != v:t_dict || !has_key(session, 'port')
    return
  endif
  let channel = ch_open('127.0.0.1:' . session.port, {'mode': 'json'})
  if ch_status(channel) !=# 'open'
    return
  endif
  call timer_stop(a:timer)
  let s:poll_timer = -1
  let s:channel = channel
  call ch_evalexpr(channel, {'auth': get(session, 'token', '')}, {'timeout': 2000})
endfunction

" ---------------------------------------------------------------------------
" The toolset the agent is allowed to use
" ---------------------------------------------------------------------------

function! vimcap#agent#dispatch(tool, args) abort
  try
    return s:in_capture_window(a:tool, a:args)
  catch
    return {'error': v:exception}
  endtry
endfunction

function! s:in_capture_window(tool, args) abort
  " Fall back to the current buffer when dispatch is used directly (tests).
  let bufnr = (s:bufnr > 0 && bufexists(s:bufnr)) ? s:bufnr : bufnr('%')
  let winid = bufwinid(bufnr)
  if winid < 0
    return {'error': 'the capture window has been closed'}
  endif
  let previous = win_getid()
  call win_gotoid(winid)
  try
    return s:run_tool(a:tool, a:args)
  finally
    call win_gotoid(previous)
  endtry
endfunction

function! s:index(args, key, default) abort
  return max([1, min([get(a:args, a:key, a:default), line('$')])])
endfunction

function! s:packet_info(index) abort
  let packets = get(get(b:, 'vimcap', {}), 'packets', [])
  let entry = a:index <= len(packets) ? packets[a:index - 1] : {}
  return {'index': a:index, 'hex': getline(a:index),
        \ 'summary': get(entry, 's', ''), 'bad_checksums': get(entry, 'bad', [])}
endfunction

function! s:tool_overview(args) abort
  let summaries = map(copy(vimcap#packet_summaries(bufnr('%'))[: 99]),
        \ {index, summary -> (index + 1) . ': ' . summary})
  return {'file': expand('%:p'), 'linktype': vimcap#linktype(bufnr('%')),
        \ 'packet_count': line('$'), 'summaries': summaries}
endfunction

function! s:tool_packets(args) abort
  let from = s:index(a:args, 'from', 1)
  let to = s:index(a:args, 'to', from + 19)
  return {'packets': map(range(from, to), {_, n -> s:packet_info(n)})}
endfunction

function! s:tool_detail(args) abort
  let index = s:index(a:args, 'index', line('.'))
  return {'detail': join(vimcap#detail_lines(bufnr('%'), index, ''), "\n")}
endfunction

function! s:tool_goto(args) abort
  let index = s:index(a:args, 'index', line('.'))
  let byte = get(a:args, 'byte', 0)
  call cursor(index, byte * 3 + 1)
  normal! zv
  call vimcap#track_cursor()
  redraw
  return {'position': 'packet ' . index . ' byte ' . byte,
        \ 'field': vimcap#describe_byte(index, byte)}
endfunction

function! s:tool_set_field(args) abort
  let index = s:index(a:args, 'index', line('.'))
  call cursor(index, 1)
  call vimcap#set_field(get(a:args, 'spec', ''))
  redraw
  return s:packet_info(index)
endfunction

function! s:tool_fix(args) abort
  let from = s:index(a:args, 'from', 1)
  let to = s:index(a:args, 'to', line('$'))
  call vimcap#fix(from, to)
  redraw
  return {'packets': map(range(from, to), {_, n -> s:packet_info(n)})}
endfunction

function! s:tool_replace(args) abort
  let index = s:index(a:args, 'index', 0)
  let hex = get(a:args, 'hex', '')
  if hex !~? '^\s*\%(\x\x\s*\)\+$'
    return {'error': 'hex must be space-separated byte pairs'}
  endif
  call setline(index, substitute(tolower(hex), '\s\+', ' ', 'g'))
  call vimcap#live#flush(bufnr('%'))
  redraw
  return s:packet_info(index)
endfunction

function! s:tool_insert(args) abort
  let response = vimcap#api({'op': 'craft', 'expr': get(a:args, 'expr', '')})
  if !has_key(response, 'hex')
    return {'error': 'expression did not produce a packet'}
  endif
  let after = max([0, min([get(a:args, 'after', line('$')), line('$')])])
  call append(after, response.hex)
  call vimcap#live#flush(bufnr('%'))
  redraw
  return s:packet_info(after + 1)
endfunction

function! s:tool_delete(args) abort
  execute s:index(a:args, 'index', 0) . 'delete _'
  call vimcap#live#flush(bufnr('%'))
  redraw
  return {'packet_count': line('$')}
endfunction

function! s:tool_filter(args) abort
  call vimcap#filter(0, get(a:args, 'expr', ''))
  redraw
  return {'matching': sort(map(keys(get(b:, 'vimcap_filter_match', {})),
        \ {_, k -> str2nr(k)}), 'n')}
endfunction

function! s:tool_clear_filter(args) abort
  call vimcap#filter(1, '')
  redraw
  return {'ok': v:true}
endfunction

function! s:tool_follow(args) abort
  call cursor(s:index(a:args, 'index', line('.')), 1)
  call vimcap#follow()
  redraw
  let stream = bufnr('vimcap://stream')
  return {'stream': stream > 0 ? join(getbufline(stream, 1, '$'), "\n") : ''}
endfunction

function! s:tool_grep(args) abort
  let response = vimcap#api({'op': 'grep', 'pattern': get(a:args, 'pattern', ''),
        \ 'packets': getline(1, '$')})
  return {'matches': get(response, 'matches', [])}
endfunction

function! s:tool_stats(args) abort
  let response = vimcap#api({'op': 'stats', 'linktype': vimcap#linktype(bufnr('%')),
        \ 'packets': getline(1, '$'), 'times': vimcap#packet_times(bufnr('%'))})
  return {'stats': join(get(response, 'lines', []), "\n")}
endfunction

function! s:tool_ex(args) abort
  if !get(g:, 'vimcap_agent_raw', 0)
    return {'error': 'raw ex commands are disabled; the user can enable '
          \ . 'them with g:vimcap_agent_raw = 1'}
  endif
  return {'output': execute(get(a:args, 'command', ''))}
endfunction

" Tool name -> handler. Keep the keys in step with AGENT_TOOLS in vimcap.py,
" which advertises the same catalogue to the agent.
let s:tools = {
      \ 'overview': function('s:tool_overview'),
      \ 'packets': function('s:tool_packets'),
      \ 'detail': function('s:tool_detail'),
      \ 'goto': function('s:tool_goto'),
      \ 'set_field': function('s:tool_set_field'),
      \ 'fix': function('s:tool_fix'),
      \ 'replace': function('s:tool_replace'),
      \ 'insert': function('s:tool_insert'),
      \ 'delete': function('s:tool_delete'),
      \ 'filter': function('s:tool_filter'),
      \ 'clear_filter': function('s:tool_clear_filter'),
      \ 'follow': function('s:tool_follow'),
      \ 'grep': function('s:tool_grep'),
      \ 'stats': function('s:tool_stats'),
      \ 'ex': function('s:tool_ex')}

function! s:run_tool(tool, args) abort
  if !has_key(s:tools, a:tool)
    return {'error': 'unknown tool: ' . a:tool}
  endif
  return s:tools[a:tool](a:args)
endfunction
