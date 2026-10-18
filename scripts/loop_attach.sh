#!/usr/bin/env bash
# Attach an image you own as a loop device and print the device path.
# Uses udisks (no sudo needed on a desktop session), falling back to `sudo losetup`.
#
# usage: scripts/loop_attach.sh <image>
set -euo pipefail
img=$(realpath "${1:?usage: $0 <image>}")
[[ -f $img ]] || { echo "$img is not a regular file" >&2; exit 1; }
[[ $(stat -c %u "$img") == "$(id -u)" ]] || { echo "$img is not owned by you" >&2; exit 1; }
if existing=$(losetup -j "$img" | cut -d: -f1) && [[ -n $existing ]]; then
    echo "$img already attached as $existing" >&2; echo "$existing"; exit 0
fi

if command -v udisksctl >/dev/null &&
   out=$(udisksctl loop-setup --no-user-interaction -f "$img" 2>&1); then
    dev=$(grep -o '/dev/loop[0-9]*' <<<"$out")
else
    dev=$(sudo losetup --find --show "$img")
fi
echo "attached $img as $dev (open it with: sudo ./build/datawipe ... $dev)" >&2
echo "$dev"
