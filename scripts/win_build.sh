#!/usr/bin/env bash
# Cross-builds datawipe.exe in build-win/ and, with --test, runs the unit suites and the image
# end-to-end script against it under Wine. Needs scripts/win_toolchain.sh to have run.
# usage: scripts/win_build.sh [--test]
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
C=${DW_WIN_CACHE:-$HOME/.cache/datawipe-win}
[[ -f $C/openssl/lib/libcrypto.a ]] || { echo "run scripts/win_toolchain.sh first" >&2; exit 2; }
B=$here/build-win
cmake -S "$here" -B "$B" -DCMAKE_TOOLCHAIN_FILE="$here/cmake/mingw-w64-x86_64.cmake" -DDW_MINGW_ROOT="$C/root" \
    -DOPENSSL_ROOT_DIR="$C/openssl" -DOPENSSL_USE_STATIC_LIBS=ON -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build "$B" -j"$(nproc)"
"$C/root/usr/bin/x86_64-w64-mingw32-strip" "$B/datawipe.exe"
ls -lh "$B/datawipe.exe"
[[ ${1:-} == --test ]] || exit 0

fail=0
for t in test_json test_ata_identity test_device test_engine test_hardware test_overwrite test_verify test_arvs test_tecc test_win_storage; do
    # A crash would start Wine's debugger and wait forever: bound every suite.
    if (cd "$B" && DW_PROFILES_DIR=$here/profiles timeout 900 "$here/scripts/wine_run.sh" "$t.exe" >"$B/$t.log" 2>&1); then
        echo "  ok    $t"
    else
        echo "  FAIL  $t (see $B/$t.log)"; fail=1
    fi
done
printf '#!/bin/sh\nexec "%s/scripts/wine_run.sh" "%s/datawipe.exe" "$@"\n' "$here" "$B" >"$B/datawipe-wine"
chmod +x "$B/datawipe-wine"
# One e2e check compares the medium path with the Unix spelling, which Wine reports as Z:\...;
# it is expected to fail here and nowhere else.
out=$(cd "$B" && DATAWIPE=$B/datawipe-wine PROFILES=$here/profiles "$here/scripts/e2e.sh" 2>&1) || true
echo "$out" | grep -E "FAIL|passed, "
unexpected=$(echo "$out" | grep "FAIL" | grep -vc "certificate names the image as the medium" || true)
(( unexpected == 0 )) || fail=1
exit $fail
