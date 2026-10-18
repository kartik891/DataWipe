#!/usr/bin/env bash
# Run a Windows program from build-win/ under the locally unpacked Wine (scripts/win_toolchain.sh).
# usage: scripts/wine_run.sh <program.exe> [args...]
C=${DW_WIN_CACHE:-$HOME/.cache/datawipe-win}
W=$C/wine/usr/lib/x86_64-linux-gnu/wine
[[ -x $W/wine ]] || { echo "no Wine at $W: run scripts/win_toolchain.sh" >&2; exit 77; }
# This Wine build looks for its data in a fixed place; wineserver was pointed here (win_toolchain.sh).
ln -sfn "$C/wine/usr/share/wine" /tmp/dw-wineshr
export WINEPREFIX=$C/prefix WINEDLLPATH=$W WINEDEBUG=${WINEDEBUG:--all}
exec "$W/wine" "$@"
