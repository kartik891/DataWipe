#!/usr/bin/env bash
# End-to-end test of the datawipe CLI against a disk image, the way an operator uses it:
#
#   dd-style 100 MiB image with a known plaintext  ->  [losetup]  ->  probe -> plan -> run
#   -> the plaintext is gone and the image is incompressible -> certificate checks out
#   -> `verify` re-reads the medium from the certificate -> corruption and tampering are caught
#   -> Ctrl-C mid-wipe, refused rerun, refused mismatched resume, --resume completes it
#   -> SSD plan is simulated (medium unchanged) -> unsafe targets are refused
#
# usage: scripts/e2e.sh [--loop] [--keep]
#   --loop   run every wipe through a loop device (losetup) backed by the image. Needs root:
#            sudo scripts/e2e.sh --loop   (images are created as, and owned by, $SUDO_USER)
#   --keep   leave the work directory for inspection
# env: DATAWIPE (binary, default build/datawipe), PROFILES (default profiles/)
# exit: 0 all checks passed, 1 some failed, 77 skipped (ctest SKIP_RETURN_CODE)

set -uo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
DATAWIPE=$(realpath "${DATAWIPE:-$here/build/datawipe}")
PROFILES=$(realpath "${PROFILES:-$here/profiles}")
MK_IMAGE="$here/scripts/mk_test_image.sh"
loop=0 keep=0
for a in "$@"; do
    case $a in
        --loop) loop=1 ;;
        --keep) keep=1 ;;
        *) echo "usage: $0 [--loop] [--keep]" >&2; exit 2 ;;
    esac
done
[[ -x $DATAWIPE ]] || { echo "no datawipe binary at $DATAWIPE (build first)" >&2; exit 2; }
if (( loop )); then
    [[ $EUID -eq 0 && -n ${SUDO_UID:-} ]] || { echo "--loop needs root via sudo: sudo $0 --loop" >&2; exit 77; }
fi

# Not /tmp: tmpfs may refuse O_DIRECT, and images belong next to the build anyway.
W=$(mktemp -d "$PWD/dw_e2e_XXXXXX")
loops=()
cleanup() {
    for l in "${loops[@]}"; do [[ -n $l ]] && losetup -d "$l" 2>/dev/null; done
    if (( keep )); then echo "work directory kept: $W"; else rm -rf "$W"; fi
}
trap cleanup EXIT
(( loop )) && chown "$SUDO_UID:$SUDO_GID" "$W"

pass=0 fail=0
ok()  { pass=$((pass + 1)); printf '  ok    %s\n' "$1"; }
bad() { fail=$((fail + 1)); printf '  FAIL  %s\n' "$1"; [[ -n ${2:-} && -f $2 ]] && sed 's/^/        | /' "$2" | tail -15; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

# expect <exit code> <description> -- <command...>; output goes to $W/last.log
expect() {
    local want=$1 what=$2; shift 3
    "$@" >"$W/last.log" 2>&1
    local got=$?
    if [[ $got -eq $want ]]; then ok "$what (exit $got)"; else bad "$what: exit $got, expected $want" "$W/last.log"; fi
}

# A fresh image of $2 MiB with the plaintext pattern, owned by the invoking user.
image() {
    "$MK_IMAGE" "$W/$1" "$2" >/dev/null
    (( loop )) && chown "$SUDO_UID:$SUDO_GID" "$W/$1"
    echo "$W/$1"
}
# Sets TGT to the path to wipe: the image itself, or a loop device backed by it. (Not called
# in $(...): the loop list must reach the cleanup trap.)
attach() {
    TGT=$1
    if (( loop )); then
        TGT=$(losetup --find --show "$1") || { echo "losetup $1 failed" >&2; exit 1; }
        loops+=("$TGT")
    fi
}
plaintext_lines() { grep -c DATAWIPE-TEST "$1"; }

echo "datawipe end-to-end ($("$DATAWIPE" --version), $( ((loop)) && echo 'loop device' || echo 'image file') mode)"
echo "work directory: $W"

# The organisation's TECC signing key: every run below signs its certificate.
export DATAWIPE_KEY_PASSPHRASE='e2e passphrase, not secret'
"$DATAWIPE" keygen "$W/org" >/dev/null || { echo "keygen failed" >&2; exit 1; }
export DATAWIPE_SIGN_KEY=$W/org.key.pem

# ---------------------------------------------------------------------------------------------
echo "== 1. 100 MiB image -> probe -> plan -> run -> verify"
IMG=$(image disk.img 100)
attach "$IMG"; T=$TGT
[[ $T != "$IMG" ]] && echo "  (wiping through $T, backed by $IMG)"
before=$(plaintext_lines "$IMG")
check "image starts with $before plaintext lines" "(( before == 100 * 1024 * 1024 / 64 ))"

expect 0 "probe" -- "$DATAWIPE" probe "$T" --identity "$PROFILES/hdd_basic.json" --json
check "probe classifies the drive as an HDD" "grep -q '\"media\": \"HDD\"' '$W/last.log'"
expect 0 "plan" -- "$DATAWIPE" plan "$T" --identity "$PROFILES/hdd_basic.json"
check "plan is overwrite + ATA Secure Erase (Purge)" "grep -q 'hdd.overwrite+ata-se-enhanced' '$W/last.log'"
check "plan left the image untouched" "(( \$(plaintext_lines '$IMG') == before ))"

CERT=$W/disk.cert.json
expect 0 "run" -- "$DATAWIPE" run "$T" --identity "$PROFILES/hdd_basic.json" --cert "$CERT"
cp "$W/last.log" "$W/run.log"
check "run reports SUCCESS, achieved Purge" "grep -q 'Result  *SUCCESS, achieved Purge' '$W/run.log'"
check "run's read-back PASSED" "grep -q 'Verification  *PASSED' '$W/run.log'"
check "verification used ARVS with high-risk clusters" "grep -q 'arvs .* unit(s)' '$W/run.log' && grep -q 'in the high-risk region' '$W/run.log'"
check "SCI is 100 on a clean wipe" "grep -q 'SCI  *100.00 / 100' '$W/run.log'"
check "certificate carries the SCI score" "grep -q '\"sci_score\": 100' '$CERT'"
check "certificate records the AHP weights" "grep -q '\"gamma_F\"' '$CERT' && grep -q '\"consistency_ratio\"' '$CERT'"
check "no plaintext line survives" "(( \$(plaintext_lines '$IMG') == 0 ))"
compressed=$(gzip -1 -c "$IMG" | wc -c)
check "image no longer compresses (gzip: $compressed of $((100 << 20)) bytes)" "(( compressed > (100 << 20) ))"
check "no journal left behind" "! ls '$W'/*.dwjournal >/dev/null 2>&1"
check "certificate written" "[[ -s '$CERT' ]]"
check "certificate outcome is sanitized" "grep -q '\"outcome\": \"sanitized\"' '$CERT'"
check "certificate names the image as the medium" "grep -q '$IMG' '$CERT'"

expect 0 "verify-cert" -- "$DATAWIPE" verify-cert "$CERT"
expect 0 "verify the medium from its certificate" -- "$DATAWIPE" verify "$T" --cert "$CERT"
if (( loop )); then
    # The guard refuses an image while a loop device is attached to it, so detach first; the
    # certificate then still checks the image on its own, as it would on a later day.
    losetup -d "$T" && loops=("${loops[@]/$T}")
    T=$IMG
    expect 0 "after losetup -d, verify the image file from the same certificate" -- \
        "$DATAWIPE" verify "$IMG" --cert "$CERT"
fi
expect 0 "verify every sector (uniform sampler, sample = whole disk)" -- \
    "$DATAWIPE" verify "$T" --cert "$CERT" --sampler uniform --verify-samples 204800
check "exhaustive verify read all 204800 sectors" "grep -q '204800 of 204800 sectors read' '$W/last.log'"

# ---------------------------------------------------------------------------------------------
echo "== 1b. TECC: signed certificate, session log, PDF"
check "certificate is signed with Ed25519" "grep -q '\"algorithm\": \"Ed25519\"' '$CERT'"
check "session log and PDF written next to it" "[[ -s '$W/disk.cert.dwlog.jsonl' && -s '$W/disk.cert.pdf' ]]"
expect 0 "auditor check: certificate + published key + session log" -- \
    "$DATAWIPE" verify-cert "$CERT" --pubkey "$W/org.pub.pem"
check "  ...signature valid for the trusted key" "grep -q 'VALID, by the trusted key' '$W/last.log'"
check "  ...whole history chained" \
    "grep -q 'detection -> plan -> execution -> verification -> certificate' '$W/last.log'"
expect 0 "the PDF alone verifies (signed JSON attached)" -- "$DATAWIPE" verify-cert "$W/disk.cert.pdf" --pubkey "$W/org.pub.pem"
"$DATAWIPE" keygen "$W/other" >/dev/null
expect 8 "a certificate is refused against another organisation's key" -- \
    "$DATAWIPE" verify-cert "$CERT" --pubkey "$W/other.pub.pem"
python3 - "$CERT" "$W/badsig.json" <<'PY'
import json, sys
c = json.load(open(sys.argv[1]))
v = c["tecc"]["signature"]["value"]
c["tecc"]["signature"]["value"] = ("1" if v[0] == "0" else "0") + v[1:]  # one flipped digit
json.dump(c, open(sys.argv[2], "w"), indent=2)
PY
expect 8 "a forged signature under the organisation's key is caught" -- \
    "$DATAWIPE" verify-cert "$W/badsig.json" --pubkey "$W/org.pub.pem"
check "  ...as an invalid signature" "grep -q 'signature INVALID' '$W/last.log'"
sed '3s/"plan_sha256":"/"plan_sha256":"f/' "$W/disk.cert.dwlog.jsonl" > "$W/tampered.dwlog.jsonl"
expect 8 "an edited session log is caught" -- \
    "$DATAWIPE" verify-cert "$CERT" --pubkey "$W/org.pub.pem" --log "$W/tampered.dwlog.jsonl"

# ---------------------------------------------------------------------------------------------
echo "== 2. corruption and tampering are detected"
# 10 MiB of old data reappears (10% of the disk: a sample of 4603 cannot miss it).
dd if=/dev/zero of="$IMG" bs=1M count=10 seek=40 conv=notrunc,fsync status=none
expect 8 "verify catches a 10 MiB region that is not the pattern" -- "$DATAWIPE" verify "$T" --cert "$CERT"
check "verify names mismatched sectors inside it" \
    "grep -oE 'mismatched sectors: [0-9]+' '$W/last.log' | awk '{exit !(\$3 >= 81920 && \$3 < 102400)}'"

sed 's/SIMHDD-0001/SIMHDD-0002/' "$CERT" > "$W/tampered.json"
expect 8 "verify-cert catches an edited serial number" -- "$DATAWIPE" verify-cert "$W/tampered.json"
expect 8 "verify refuses a tampered certificate" -- "$DATAWIPE" verify "$T" --cert "$W/tampered.json"
python3 -c 'import json,sys; json.dump(json.load(open(sys.argv[1])), open(sys.argv[2], "w"))' \
    "$CERT" "$W/compact.json" 2>/dev/null && \
    expect 0 "a re-indented certificate still verifies" -- "$DATAWIPE" verify-cert "$W/compact.json"

SMALL=$(image small.img 4)
expect 2 "verify refuses a different medium" -- "$DATAWIPE" verify "$SMALL" --cert "$CERT"
check "  ...because its size differs from the certified one" "grep -q 'not the medium that was wiped' '$W/last.log'"

# ---------------------------------------------------------------------------------------------
echo "== 3. interrupt, refused rerun, refused mismatched resume, resume"
BIG=$(image big.img 512)
attach "$BIG"; TB=$TGT
JOURNAL=$BIG.dwjournal
"$DATAWIPE" run "$TB" --identity "$PROFILES/hdd_basic.json" --buffer-size 1M --sync-every 8M \
    --cert "$W/big.cert.json" >"$W/int.log" 2>&1 &
pid=$!
# Interrupt inside the final pass (step 2), so the seam lies in the content verification reads.
for _ in $(seq 400); do grep -q '== Step 2/2' "$W/int.log" 2>/dev/null && break; sleep 0.02; done
sleep 0.3
kill -INT $pid 2>/dev/null
wait $pid
code=$?
if [[ $code -eq 0 ]]; then
    echo "  skip  the 512 MiB wipe finished before Ctrl-C arrived; interruption not exercised"
else
    check "Ctrl-C stops the run with exit 7 (got $code)" "(( code == 7 ))"
    check "the run says it was INTERRUPTED" "grep -q 'Result  *INTERRUPTED' '$W/int.log'"
    check "journal kept at $JOURNAL" "[[ -s '$JOURNAL' ]]"
    check "no certificate for an interrupted wipe" "[[ ! -e '$W/big.cert.json' ]]"
    expect 2 "plain rerun refused while a journal exists" -- \
        "$DATAWIPE" run "$TB" --identity "$PROFILES/hdd_basic.json"
    check "  ...and points to --resume / --restart" "grep -q 'Continue it with --resume' '$W/last.log'"
    expect 2 "resume with a different drive profile refused" -- \
        "$DATAWIPE" run "$TB" --identity "$PROFILES/hdd_frozen.json" --resume
    check "  ...because the journal names another drive" "grep -q 'journal does not match this target' '$W/last.log'"
    LOGF=$W/big.cert.dwlog.jsonl
    cp "$LOGF" "$W/log.bak"
    sed -i '2s/"serial":"SIMHDD-0001"/"serial":"SIMHDD-9999"/' "$LOGF"
    expect 2 "resume refused after the session log was edited while paused" -- \
        "$DATAWIPE" run "$TB" --identity "$PROFILES/hdd_basic.json" --resume --cert "$W/big.cert.json"
    check "  ...naming the modified entry" "grep -q 'content does not match its hash' '$W/last.log'"
    cp "$W/log.bak" "$LOGF"
    expect 0 "--resume completes the wipe" -- \
        "$DATAWIPE" run "$TB" --identity "$PROFILES/hdd_basic.json" --resume --cert "$W/big.cert.json"
    check "resumed run's read-back PASSED" "grep -q 'Verification  *PASSED' '$W/last.log'"
    check "journal removed after completion" "[[ ! -e '$JOURNAL' ]]"
    check "certificate records 2 runs" "grep -q '\"runs\": 2' '$W/big.cert.json'"
    expect 0 "the resumed session verifies end to end" -- "$DATAWIPE" verify-cert "$W/big.cert.json" --pubkey "$W/org.pub.pem"
    check "  ...its log records the interruption and the resume" "grep -q 'detection -> plan -> interrupted -> resume -> execution -> verification -> certificate' '$W/last.log'"
    check "the resume seam is an ARVS boundary" \
        "grep -A1 '\"resume_boundaries\": \\[' '$W/big.cert.json' | tail -1 | grep -qE '^ *[0-9]+,?$'"
    expect 0 "the resumed wipe verifies from its certificate" -- "$DATAWIPE" verify "$TB" --cert "$W/big.cert.json"
    check "no plaintext line survives the resumed wipe" "(( \$(plaintext_lines '$BIG') == 0 ))"
fi

# ---------------------------------------------------------------------------------------------
echo "== 3b. Ctrl-C during verification: nothing lost, --resume repeats only the verification"
VCERT=$W/verify.cert.json
"$DATAWIPE" run "$TB" --identity "$PROFILES/hdd_basic.json" --verify-budget 100% --fixed-budget \
    --cert "$VCERT" >"$W/vint.log" 2>&1 &
pid=$!
for _ in $(seq 1500); do grep -q '== Verify' "$W/vint.log" 2>/dev/null && break; sleep 0.02; done
sleep 0.15
kill -INT $pid 2>/dev/null
wait $pid
code=$?
if [[ $code -eq 0 ]]; then
    echo "  skip  verification finished before Ctrl-C arrived; interruption not exercised"
else
    check "Ctrl-C during verification stops with exit 7 (got $code)" "(( code == 7 ))"
    check "it says the wipe is complete and only verification remains" \
        "grep -q 'the wipe itself is complete' '$W/vint.log' && grep -q 'Result  *SUCCESS' '$W/vint.log'"
    check "the journal (with the pattern key) is kept; no certificate yet" "[[ -s '$JOURNAL' && ! -e '$VCERT' ]]"
    before_sum=$(md5sum < "$BIG")
    expect 0 "--resume repeats only the verification" -- \
        "$DATAWIPE" run "$TB" --identity "$PROFILES/hdd_basic.json" --resume --cert "$VCERT"
    check "  ...without writing to the medium again" \
        "grep -q 'repeating only its verification' '$W/last.log' && [[ \$(md5sum < '$BIG') == '$before_sum' ]]"
    check "  ...and issues the certificate; the journal is then removed" \
        "grep -q 'Verification  *PASSED' '$W/last.log' && [[ -s '$VCERT' && ! -e '$JOURNAL' ]]"
    expect 0 "its session log records the interrupted verification" -- "$DATAWIPE" verify-cert "$VCERT" --pubkey "$W/org.pub.pem"
    check "  ...execution -> verification-interrupted -> resume -> verification -> certificate" \
        "grep -q 'execution -> verification-interrupted -> resume -> verification -> certificate' '$W/last.log'"
fi

# ---------------------------------------------------------------------------------------------
echo "== 4. SSD plans are simulated: the medium is not touched"
SSD=$(image ssd.img 16)
attach "$SSD"; TS=$TGT
sum=$(md5sum < "$SSD")
expect 0 "run with an NVMe SSD profile" -- \
    "$DATAWIPE" run "$TS" --identity "$PROFILES/ssd_nvme_plain.json" --cert "$W/ssd.cert.json"
check "reported as SIMULATED" "grep -q 'SIMULATED: medium unchanged' '$W/last.log'"
check "image content unchanged" "[[ \$(md5sum < '$SSD') == '$sum' ]]"
check "certificate outcome is simulated" "grep -q '\"outcome\": \"simulated\"' '$W/ssd.cert.json'"
expect 4 "verify explains there is nothing to read back" -- "$DATAWIPE" verify "$TS" --cert "$W/ssd.cert.json"

# ---------------------------------------------------------------------------------------------
echo "== 5. unsafe or ambiguous requests are refused"
expect 2 "a character device (/dev/zero)" -- "$DATAWIPE" run /dev/zero --identity "$PROFILES/hdd_basic.json"
expect 2 "an image without --identity" -- "$DATAWIPE" run "$SMALL"
expect 2 "--resume with no interrupted wipe" -- "$DATAWIPE" run "$SMALL" --identity "$PROFILES/hdd_basic.json" --resume
expect 1 "--resume together with --restart" -- \
    "$DATAWIPE" run "$SMALL" --identity "$PROFILES/hdd_basic.json" --resume --restart
DATAWIPE_KEY_PASSPHRASE='wrong passphrase!!' expect 2 "a wrong key passphrase stops the run before anything is written" -- \
    "$DATAWIPE" run "$SMALL" --identity "$PROFILES/hdd_basic.json"
check "the refused runs left small.img intact" "(( \$(plaintext_lines '$SMALL') == 4 * 1024 * 1024 / 64 ))"

# ---------------------------------------------------------------------------------------------
echo "== 6. guided mode (datawipe interactive), answers piped in"
G=$(image guided.img 16)
attach "$G"; TG=$TGT
guided() { printf '%b' "$1" | "$DATAWIPE" interactive --state-dir "$W"; }
expect 0 "list drives without the destructive flag" -- guided '1\n\nq\n'
check "no physical disk is listed or offered" "! grep -Eq '/dev/(sd|nvme|mmcblk|vd)' '$W/last.log'"
check "it says how physical disks get listed" "grep -q 'Physical disks are hidden' '$W/last.log'"
(( loop )) && check "the loop device backed by our image is listed" "grep -q '$TG .*loop' '$W/last.log'"
expect 0 "wrong confirmation word" -- guided "3\n$TG\n$PROFILES/hdd_basic.json\nwipe\n\nq\n"
check "plan screen: steps, Purge, signed certificate announced" \
    "grep -q '1. Host overwrite' '$W/last.log' && grep -q 'Level reached .*Purge' '$W/last.log' && grep -q 'signed with $W/org.key.pem' '$W/last.log'"
check "cancelled: image untouched" "grep -q cancelled '$W/last.log' && (( \$(plaintext_lines '$G') == 16 * 1024 * 1024 / 64 ))"
expect 0 "input ends at the confirmation" -- guided "3\n$TG\n$PROFILES/hdd_basic.json\n"
check "nothing written" "(( \$(plaintext_lines '$G') == 16 * 1024 * 1024 / 64 ))"
expect 0 "wipe through the menu" -- guided "3\n$TG\n$PROFILES/hdd_basic.json\nWIPE\n\nq\n"
check "result screen says DONE; read-back PASSED; certificate signed" \
    "grep -q '  DONE  ' '$W/last.log' && grep -q 'Verification      PASSED' '$W/last.log' && grep -q 'signed with Ed25519' '$W/last.log'"
check "no plaintext left" "(( \$(plaintext_lines '$G') == 0 ))"
GC=$(ls "$G".*.dwcert.json 2>/dev/null | head -1)
expect 0 "verify that certificate through the menu" -- guided "4\n$GC\n$W/org.pub.pem\n\nq\n"
check "trusted signature, check passed" \
    "grep -q 'VALID, by the trusted key' '$W/last.log' && grep -q 'CERTIFICATE CHECK PASSED' '$W/last.log'"
expect 1 "no command and no terminal is still a usage error" -- "$DATAWIPE"

echo
echo "$pass passed, $fail failed"
(( fail == 0 ))
