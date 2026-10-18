#!/usr/bin/env bash
# Sets up what the Windows cross-build needs, without root, under ~/.cache/datawipe-win:
#   root/      MinGW-w64 (GCC 13, posix threads) unpacked from Ubuntu's packages
#   openssl/   OpenSSL libcrypto built for Windows from the official source release
#   wine/      Wine unpacked from Ubuntu's packages, to run the result here (optional: --no-wine)
# Then: scripts/win_build.sh
# With root you can instead `apt install g++-mingw-w64-x86-64-posix wine64` and build OpenSSL only.
set -euo pipefail
C=${DW_WIN_CACHE:-$HOME/.cache/datawipe-win}
OPENSSL_VERSION=3.5.5
wine=1
[[ ${1:-} == --no-wine ]] && wine=0
mkdir -p "$C"/{debs,winedebs}

if [[ ! -x $C/root/usr/bin/x86_64-w64-mingw32-g++-posix ]]; then
    echo "== MinGW-w64 cross-compiler"
    (cd "$C/debs" && apt-get download g++-mingw-w64-x86-64-posix gcc-mingw-w64-x86-64-posix \
        gcc-mingw-w64-x86-64-posix-runtime gcc-mingw-w64-base binutils-mingw-w64-x86-64 mingw-w64-x86-64-dev \
        mingw-w64-common)
    mkdir -p "$C/root"
    for d in "$C"/debs/*.deb; do dpkg-deb -x "$d" "$C/root"; done
    for t in gcc g++ cpp; do ln -sf "x86_64-w64-mingw32-$t-posix" "$C/root/usr/bin/x86_64-w64-mingw32-$t"; done
fi

if [[ ! -f $C/openssl/lib/libcrypto.a ]]; then
    echo "== OpenSSL $OPENSSL_VERSION libcrypto for Windows (a few minutes)"
    mkdir -p "$C/openssl-src" && cd "$C/openssl-src"
    base=https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz
    curl -fsSLO "$base" && curl -fsSLO "$base.sha256"
    [[ $(sha256sum < "openssl-$OPENSSL_VERSION.tar.gz" | cut -d' ' -f1) == $(cut -d' ' -f1 "openssl-$OPENSSL_VERSION.tar.gz.sha256") ]] ||
        { echo "OpenSSL checksum mismatch" >&2; exit 1; }
    tar xzf "openssl-$OPENSSL_VERSION.tar.gz" && cd "openssl-$OPENSSL_VERSION"
    PATH=$C/root/usr/bin:$PATH ./Configure mingw64 --cross-compile-prefix=x86_64-w64-mingw32- no-shared no-tests \
        no-apps no-docs no-legacy no-engine no-dso --prefix="$C/openssl" >configure.log
    PATH=$C/root/usr/bin:$PATH make -j"$(nproc)" build_generated libcrypto.a >build.log 2>&1
    mkdir -p "$C/openssl/lib" "$C/openssl/include"
    cp libcrypto.a "$C/openssl/lib/" && cp -r include/openssl "$C/openssl/include/"
fi

if (( wine )) && [[ ! -x $C/wine/usr/lib/x86_64-linux-gnu/wine/wine ]]; then
    echo "== Wine (to run the Windows build here)"
    (cd "$C/winedebs" && apt-get download wine64 libwine wine-common libz-mingw-w64)
    mkdir -p "$C/wine"
    for d in "$C"/winedebs/*.deb; do dpkg-deb -x "$d" "$C/wine"; done
    # Unpacked outside /usr, wineserver cannot find its data: point its one fixed path at a
    # same-length location that scripts/wine_run.sh links to the unpacked copy.
    python3 - "$C/wine/usr/lib/x86_64-linux-gnu/wine/wineserver" <<'PY'
import sys
p = sys.argv[1]
b = open(p, 'rb').read()
old, new = b'/usr/share/wine/nls\0', b'/tmp/dw-wineshr/nls\0'
if old in b:
    open(p, 'wb').write(b.replace(old, new))
PY
    cp "$C/wine/usr/x86_64-w64-mingw32/lib/zlib1.dll" "$C/wine/usr/lib/x86_64-linux-gnu/wine/x86_64-windows/"
    ln -sfn "$C/wine/usr/share/wine" /tmp/dw-wineshr
    WINEPREFIX=$C/prefix WINEDLLPATH=$C/wine/usr/lib/x86_64-linux-gnu/wine WINEDEBUG=-all \
        "$C/wine/usr/lib/x86_64-linux-gnu/wine/wine" cmd /c exit >/dev/null 2>&1 || true
    cp "$C/wine/usr/x86_64-w64-mingw32/lib/zlib1.dll" "$C/prefix/drive_c/windows/system32/" 2>/dev/null || true
fi
echo "toolchain ready in $C"
