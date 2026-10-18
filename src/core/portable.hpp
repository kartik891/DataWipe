#pragma once
// The few operating-system services whose POSIX and Windows forms differ in behaviour, not
// just in name (plain name gaps are filled by platform/win_compat.hpp).

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <string_view>

#ifdef _WIN32
#include <malloc.h>
#include <windows.h>
#endif

namespace dw {

// Position of the last directory separator in a path ('/' everywhere, also '\\' on Windows).
inline std::size_t last_separator(std::string_view path) {
#ifdef _WIN32
    return path.find_last_of("/\\");
#else
    return path.rfind('/');
#endif
}

// Aligned I/O buffers (O_DIRECT / unbuffered handles). Free with aligned_free only.
inline void* aligned_alloc_bytes(std::size_t alignment, std::size_t size) {
#ifdef _WIN32
    return _aligned_malloc(size, alignment);
#else
    return std::aligned_alloc(alignment, size);
#endif
}
inline void aligned_free(void* p) {
#ifdef _WIN32
    _aligned_free(p);
#else
    std::free(p);
#endif
}

// rename(2): atomically replaces `to` if it exists. Windows' rename() refuses to do that.
inline int replace_file(const char* from, const char* to) {
#ifdef _WIN32
    if (MoveFileExA(from, to, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) return 0;
    errno = GetLastError() == ERROR_ACCESS_DENIED ? EACCES : EIO;
    return -1;
#else
    return std::rename(from, to);
#endif
}

}  // namespace dw
