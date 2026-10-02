#!/usr/bin/env sh
# Provision vimcap: create a virtualenv with scapy and generate help tags.
# scapy is optional (the hex editor works without it), but installing it here
# unlocks dissection, colours, the field inspector and the whole toolbox.
#
# Run directly (./install.sh) or via a plugin manager's build hook:
#   vim-plug:   Plug 'benjaminr/vimcap', { 'do': './install.sh' }
#   lazy.nvim:  { 'benjaminr/vimcap', build = './install.sh' }

set -e
cd "$(dirname "$0")"

VENV=.venv

if command -v uv >/dev/null 2>&1; then
  echo "vimcap: creating $VENV with uv"
  uv venv "$VENV"
  uv pip install --python "$VENV/bin/python" scapy
elif command -v python3 >/dev/null 2>&1; then
  echo "vimcap: creating $VENV with python3 -m venv"
  python3 -m venv "$VENV"
  "$VENV/bin/python" -m pip install --quiet --upgrade pip
  "$VENV/bin/python" -m pip install --quiet scapy
else
  echo "vimcap: no uv or python3 found; install Python 3 first" >&2
  exit 1
fi

# Generate help tags (whichever editor is available).
if command -v vim >/dev/null 2>&1; then
  vim -u NONE -es -c 'helptags doc' -c q >/dev/null 2>&1 || true
elif command -v nvim >/dev/null 2>&1; then
  nvim --headless -c 'helptags doc' -c q >/dev/null 2>&1 || true
fi

echo "vimcap: ready — scapy installed in $VENV, picked up automatically on load"
