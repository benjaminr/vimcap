" Syntax for vimcap hex buffers: anything that is not hex is an error,
" so accidental edits stand out immediately. Layer colouring is applied
" separately with text properties / extmarks.

if exists('b:current_syntax')
  finish
endif

syntax match vimcapInvalid /[^0-9a-fA-F[:space:]]\+/
highlight default link vimcapInvalid Error

let b:current_syntax = 'vimcap'
