#!/usr/bin/env bash
# Create a disk image pre-filled with a recognisable plaintext pattern, so that a wipe is
# visibly (and verifiably) effective: `grep -c DATAWIPE-TEST image` goes from many to 0.
#
# usage: scripts/mk_test_image.sh <path> [size_MiB=100]
set -euo pipefail
path=${1:?usage: $0 <path> [size_MiB]}
mib=${2:-100}
[[ -e $path ]] && { echo "refusing to overwrite existing $path" >&2; exit 1; }

# 64-byte line: repeats cleanly across every 512-byte sector.
line='DATAWIPE-TEST-PAYLOAD sector-pattern 0123456789abcdefghijklmnop'
(( ${#line} + 1 == 64 )) || { echo "internal: pattern must be 64 bytes" >&2; exit 1; }
head -c $((mib * 1024 * 1024)) < <(yes "${line}") > "$path"  # not a pipe: yes dies of SIGPIPE, which pipefail would report
sync "$path"
echo "created $path ($mib MiB, $(grep -c DATAWIPE-TEST "$path") pattern lines)"
