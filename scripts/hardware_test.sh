#!/usr/bin/env bash
# Spare-drive hardware test: validates the firmware commands the QEMU bench cannot emulate
# (ATA Secure Erase, SANITIZE, HPA/DCO removal, NVMe Sanitize / crypto erase).
#
#   !!! THIS DESTROYS ALL DATA ON THE DRIVE YOU NAME. USE A SPARE DRIVE ONLY. !!!
#
# usage: sudo scripts/hardware_test.sh /dev/sdX|/dev/nvmeXnY [report-dir] [signing-key.pem]
#   (the key is an argument, not an environment variable: many sudo setups drop the environment)
#
# What it does (datawipe's own gate still asks you to retype the serial number and path):
#   1. probe + both plans (with and without --experimental), saved for the report
#   2. a PROVEN wipe: host overwrite, which leaves random data in every sector, so that the
#      next step's pre-wipe fingerprints are informative (a factory-blank drive would make
#      fingerprint verification inconclusive: blank before and blank after look the same)
#      (on an HDD with enhanced Secure Erase this step already includes the erase, which was
#      promoted to proven on 2026-10-10, so step 3 repeats it)
#   3. the EXPERIMENTAL wipe: the firmware method the drive supports, verified against the
#      fingerprints taken just before it
#   4. collects certificates, session logs and outputs into the report directory
#
# Send the report directory back: a command is promoted from experimental to proven only
# after it has passed here on real drives (see src/engine/command_support.cpp).
set -uo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
DATAWIPE=${DATAWIPE:-$here/build/datawipe}
[[ -x $DATAWIPE ]] || DATAWIPE=$(command -v datawipe)  # installed from a package
dev=${1:?usage: sudo $0 /dev/sdX|/dev/nvmeXnY [report-dir] [signing-key.pem]}
[[ $EUID -eq 0 ]] || { echo "run as root (sudo)" >&2; exit 2; }
[[ -b $dev ]] || { echo "$dev is not a block device" >&2; exit 2; }
[[ -t 0 ]] || { echo "run from an interactive terminal: datawipe asks you to confirm the drive" >&2; exit 2; }

name=$(basename "$dev")
report=${2:-$PWD/datawipe-hwtest-$name-$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$report" && export DATAWIPE_STATE_DIR=$report
[[ -n ${3:-} ]] && export DATAWIPE_SIGN_KEY=$3
[[ -n ${SUDO_UID:-} ]] && chown "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$report"

cat <<EOF

  Spare-drive hardware test for $dev
  Report directory: $report

  ALL DATA ON $dev WILL BE DESTROYED, TWICE. datawipe will show you the drive's model and
  serial number and ask you to retype them; stop there (Ctrl-C) if it is not your spare drive.

EOF
read -r -p "  Type YES to continue: " answer
[[ $answer == YES ]] || { echo "  stopped"; exit 1; }

step() { echo; echo "==== $*"; }
status=0

step "1/4 probe and plans"
"$DATAWIPE" probe "$dev" --json >"$report/probe.json" 2>"$report/probe.err" || status=1
"$DATAWIPE" probe "$dev" | tee "$report/probe.txt"
"$DATAWIPE" plan "$dev" >"$report/plan-proven.txt" 2>&1
"$DATAWIPE" plan "$dev" --experimental --json >"$report/plan-experimental.json" 2>&1
"$DATAWIPE" plan "$dev" --experimental | tee "$report/plan-experimental.txt"

step "2/4 proven wipe (host overwrite): fills every sector with random data"
"$DATAWIPE" run "$dev" --i-understand-this-is-destructive --cert "$report/1-proven.json" 2>&1 | tee "$report/1-proven.txt"
rc1=${PIPESTATUS[0]}
echo "exit $rc1" >>"$report/1-proven.txt"
[[ $rc1 -eq 0 ]] || { echo "proven wipe failed (exit $rc1); stopping" >&2; exit 1; }

step "3/4 EXPERIMENTAL wipe: the drive's firmware method, fingerprint-verified"
experimental() {
    "$DATAWIPE" run "$dev" --i-understand-this-is-destructive --experimental --cert "$report/$1.json" -v 2>&1 |
        tee "$report/$1.txt"
    local rc=${PIPESTATUS[0]}
    echo "exit $rc" >>"$report/$1.txt"
    return $rc
}
experimental 2-experimental
rc2=$?
if [[ $rc2 -eq 10 ]]; then
    # The drive had an HPA/DCO: stage 1 removed it. If the kernel already sees the full size,
    # the wipe itself can run now; otherwise the drive must be re-plugged or the machine rebooted.
    echo
    echo "  Hidden area removed. If datawipe said the kernel now sees the full size, the wipe can run"
    echo "  now; otherwise answer N, reboot or re-plug the drive, and run this script again."
    read -r -p "  Run the wipe now? [y/N] " go
    if [[ $go == [yY] ]]; then
        experimental 3-experimental-full
        rc2=$?
    fi
fi
[[ $rc2 -eq 0 ]] || status=1

step "4/4 report"
"$DATAWIPE" probe "$dev" --json >"$report/probe-after.json" 2>&1  # security state after the erase
{
    echo "datawipe $("$DATAWIPE" --version)"
    echo "kernel $(uname -r)"
    echo "device $dev"
    echo "proven wipe exit $rc1, experimental wipe exit $rc2"
    grep -hE '"method_id"|"outcome"|"status"' "$report"/2-experimental.json 2>/dev/null | head -5
} | tee "$report/SUMMARY.txt"
[[ -n ${SUDO_UID:-} ]] && chown -R "$SUDO_UID:${SUDO_GID:-$SUDO_UID}" "$report"
echo
echo "  Done. Send back the whole directory: $report"
exit $status
