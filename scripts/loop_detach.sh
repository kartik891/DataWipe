#!/usr/bin/env bash
# Detach a loop device, only if it is backed by a file you own.
# usage: scripts/loop_detach.sh /dev/loopN
set -euo pipefail
dev=${1:?usage: $0 /dev/loopN}
[[ $dev =~ ^/dev/loop[0-9]+$ ]] || { echo "$dev is not a loop device" >&2; exit 1; }
name=${dev#/dev/}
backing=$(cat "/sys/block/$name/loop/backing_file" 2>/dev/null) || { echo "$dev is not attached" >&2; exit 1; }
[[ $(stat -c %u "$backing") == "$(id -u)" ]] || { echo "refusing: $dev is backed by $backing, not yours" >&2; exit 1; }
udisksctl loop-delete --no-user-interaction -b "$dev" 2>/dev/null || sudo losetup -d "$dev"
echo "detached $dev ($backing)" >&2
