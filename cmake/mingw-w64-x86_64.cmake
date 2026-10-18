# Cross-compile datawipe.exe on Linux with MinGW-w64 (posix threads variant).
#   cmake -S . -B build-win -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-w64-x86_64.cmake \
#         -DDW_MINGW_ROOT=<dir holding usr/bin/x86_64-w64-mingw32-g++-posix> -DOPENSSL_ROOT_DIR=<mingw openssl>
# scripts/win_toolchain.sh fetches both without root and prints the command.
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64)
set(DW_MINGW_ROOT "" CACHE PATH "prefix of an unpacked MinGW-w64 toolchain; empty = the system one")
if(DW_MINGW_ROOT)
  set(_dw_bin "${DW_MINGW_ROOT}/usr/bin/")
endif()
set(CMAKE_CXX_COMPILER "${_dw_bin}x86_64-w64-mingw32-g++-posix")
set(CMAKE_C_COMPILER "${_dw_bin}x86_64-w64-mingw32-gcc-posix")
set(CMAKE_RC_COMPILER "${_dw_bin}x86_64-w64-mingw32-windres")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_TRY_COMPILE_PLATFORM_VARIABLES DW_MINGW_ROOT)
