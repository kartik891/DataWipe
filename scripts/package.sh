#!/usr/bin/env bash
# Release build: an optimised binary in build-release/, tested, then packaged into dist/:
#   datawipe_<ver>_<arch>.deb             Debian/Ubuntu package
#   datawipe-<ver>-linux-<arch>.tar.gz    the same files under usr/, for other distributions
#   datawipe-<ver>-live.iso               bootable image (unless --no-iso)
#   datawipe-<ver>-windows-x86_64-preview.zip   datawipe.exe, image files only (if the cross toolchain exists)
#   SHA256SUMS
# usage: scripts/package.sh [--no-iso] [--no-tests]
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
iso=1 tests=1
for a in "$@"; do
    case $a in
        --no-iso) iso=0 ;;
        --no-tests) tests=0 ;;
        *) echo "usage: $0 [--no-iso] [--no-tests]" >&2; exit 2 ;;
    esac
done
B=$here/build-release D=$here/dist
cmake -S "$here" -B "$B" -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build "$B" -j"$(nproc)"
# The unit suites and the image end-to-end run, against the binary that is about to ship.
(( tests )) && (cd "$B" && ctest -E 'qemu_bench|iso_boot' --output-on-failure)
(cd "$B" && cpack >/dev/null)
ver=$("$B/datawipe" --version | cut -d' ' -f2)
rm -rf "$D" && mkdir -p "$D"
cp "$B"/datawipe_*.deb "$B"/datawipe-*.tar.gz "$D/"
if (( iso )); then
    "$here/scripts/build_iso.py" --datawipe "$B/datawipe" --out "$D/datawipe-$ver-live.iso"
    rm -f "$D/datawipe-$ver-live.iso.sha256"
fi
# Windows preview (image files only), when the cross toolchain is set up (scripts/win_toolchain.sh).
if [[ -f ${DW_WIN_CACHE:-$HOME/.cache/datawipe-win}/openssl/lib/libcrypto.a ]]; then
    if (( tests )); then "$here/scripts/win_build.sh" --test; else "$here/scripts/win_build.sh"; fi
    python3 - "$here" "$D/datawipe-$ver-windows-x86_64-preview.zip" "datawipe-$ver-windows" <<'PY'
import sys, zipfile, pathlib
here, out, top = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    z.write(here / "build-win/datawipe.exe", f"{top}/datawipe.exe")
    z.write(here / "packaging/README-WINDOWS.txt", f"{top}/README-WINDOWS.txt")
    z.write(here / "README.md", f"{top}/README.md")
    z.write(here / "packaging/copyright", f"{top}/copyright.txt")
    z.write(here / "LICENSE", f"{top}/LICENSE.txt")
    z.write(here / "packaging/QUICKSTART.txt", f"{top}/QUICKSTART.txt")
    for p in sorted((here / "profiles").glob("*.json")):
        z.write(p, f"{top}/profiles/{p.name}")
PY
else
    echo "(no Windows toolchain: skipping the Windows preview; see scripts/win_toolchain.sh)"
fi
cp "$here/packaging/QUICKSTART.txt" "$D/QUICKSTART.txt"  # next to the packages, for whoever receives them
cp "$here/DEPENDENCIES.txt" "$D/DEPENDENCIES.txt"
cp "$here/HOW_IT_WORKS.txt" "$D/HOW_IT_WORKS.txt"
(cd "$D" && sha256sum -- * >SHA256SUMS)
echo
echo "release $ver in $D:"
ls -lh "$D"
