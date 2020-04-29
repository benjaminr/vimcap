" Vim global plugin for editing pcaps as hex 
" Last change:   27 04 2020
" Maintainer:    Benjamin Rowell <brrowell@gmail.com>
" License:       This file is placed in the public domain.

" Check if we're loaded
if exists("g:vimcap_loaded")
        finish
endif
let g:vimcap_loaded = 1

" The location of this plugin
let g:vimcap_dir_path = expand('<sfile>:p:h')

" Prepare the editor for hex editing
" Allow for user customisations
function! g:Vimcap_init()
	" Jump along by 3 chars, so you're on byte boundaries
	nmap h 3<Left>
	nmap l 3<Right>

	set number

	" Get rid of wrapping, one packet per line
	set nowrap
	set formatoptions-=t

	" Remappings
	nnoremap >u :call HexToUni()<CR>
	nnoremap >a :call HexToAscii()<CR>

	windo set cursorcolumn | set cursorbind | set cursorline | set scrollbind

	" Colours
	let s:cursorline_fg = get(g:, 'vimcap_colours_cursorline_fg', 'black')
	let s:cursorline_bg = get(g:, 'vimcap_colours_cursorline_bg', 'darkblue')
	let s:cursorcolumn_fg = get(g:, 'vimcap_colours_cursorcolumn_fg', 'black')
	let s:cursorcolumn_bg = get(g:, 'vimcap_colours_cursorcolumn_bg', 'darkblue')

	" Highlight the current packet in focus along Y
	set cursorline        
	exe 'hi CursorLine cterm=NONE ctermbg=' 
				\. s:cursorline_bg 
				\. ' ctermfg=' 
				\. s:cursorline_fg 
				\. ' guibg=' 
				\. s:cursorline_bg 
				\. ' guifg=' 
				\. s:cursorline_fg

	" Highlight the current byte position in focus along X
	set cursorcolumn 
	exe 'hi CursorColumn cterm=NONE ctermbg=' 
				\. s:cursorcolumn_bg 
				\. ' ctermfg=' 
				\. s:cursorcolumn_fg 
				\. ' guibg=' 
				\. s:cursorcolumn_bg 
				\. ' guifg=' 
				\. s:cursorcolumn_fg
	
	" Stop gg and G from jumping to the start of the line
	set nostartofline

	" hl pattern matches
	set hlsearch
	hi Search cterm=NONE ctermbg=red ctermfg=black guibg=red guifg=black

	" Cursor highlights
	hi Cursor cterm=reverse ctermbg=darkblue ctermfg=black guibg=darkblue guifg=black
	hi iCursor cterm=reverse ctermbg=darkblue ctermfg=black guibg=darkblue guifg=black
	
	" Highlight which byte the cursor is focussed on
	hi cursorlocation cterm=reverse ctermbg=darkblue ctermfg=black guibg=darkblue guifg=black
	match cursorlocation /\k*\%#\k*/
endfunction

function! LoadPcap(...)
	if a:0 > 0
		call g:Vimcap_init()
		let cmd = "%!python3 " . g:vimcap_dir_path . "/vimcap.py -l " . a:1 
	else
		let vimcap_input = expand("%:p")
		let cmd = "%!python3 " . g:vimcap_dir_path . "/vimcap.py -l " . vimcap_input 
	endif
	silent execute cmd
endfunction

function! WritePcap(...)
	if a:0 > 0
		let cmd = "%!python3 " . g:vimcap_dir_path . "/vimcap.py -w " . a:1 
	else
		let vimcap_output = expand("%:p")
		let cmd = "%!python3 " . g:vimcap_dir_path . "/vimcap.py -w " . vimcap_output
	endif
	silent execute cmd
endfunction

function! FilterToNewWindow(script, split_choice)
    let cursor_pos = getpos(".")
    let TempFile = tempname() . '.vimcap.tmp'
    let SaveModified = &modified
    exe 'w ' . TempFile
    let &modified = SaveModified
    exe a:split_choice . ' ' . TempFile
    silent exe '%! ' . a:script
    call cursor(cursor_pos[1], cursor_pos[2])
endfunction

function! HexToAscii()
	" Display the current buffer hex as ascii in split
	let cmd = " python3 " . g:vimcap_dir_path . "/vimcap.py -a" 
	call FilterToNewWindow(cmd, 'split')
	resize 10
endfunction

function! HexToUni()
	" Display the current buffer hex as unicode in split
	let cmd = " python3 " . g:vimcap_dir_path . "/vimcap.py -u" 
	call FilterToNewWindow(cmd, 'split')
	resize 10
	set nocursorcolumn
endfunction

function! ScapyPrint(encap)
	" Display the current buffer hex as a Scapy Packet in vplit
	let cmd = " python3 " . g:vimcap_dir_path . "/vimcap.py -p " . a:encap 
	call FilterToNewWindow(cmd, 'split')
	resize 10
	set nocursorcolumn
endfunction

au BufNewFile,BufRead *.pcap call g:Vimcap_init() | call LoadPcap()
au BufWriteCmd *.pcap call WritePcap()
au WinEnter *.pcap,*.vimcap.tmp call g:Vimcap_init()
au BufReadPost * if line("'\"") > 0 && line("'\"") <= line("$") | exe "normal! g`\"" | endif