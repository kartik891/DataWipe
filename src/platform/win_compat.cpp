#include "platform/win_compat.hpp"

#include <windows.h>

#include <bcrypt.h>

#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <initializer_list>

namespace {

// Enough of the Win32 error space for messages to make sense through strerror().
int errno_from_win32(DWORD e) {
    switch (e) {
        case ERROR_FILE_NOT_FOUND:
        case ERROR_PATH_NOT_FOUND:
        case ERROR_INVALID_DRIVE:
        case ERROR_BAD_NETPATH: return ENOENT;
        case ERROR_ACCESS_DENIED:
        case ERROR_WRITE_PROTECT:
        case ERROR_PRIVILEGE_NOT_HELD: return EACCES;
        case ERROR_SHARING_VIOLATION:
        case ERROR_LOCK_VIOLATION:
        case ERROR_BUSY: return EBUSY;
        case ERROR_INVALID_HANDLE: return EBADF;
        case ERROR_NOT_ENOUGH_MEMORY:
        case ERROR_OUTOFMEMORY: return ENOMEM;
        case ERROR_INVALID_PARAMETER: return EINVAL;
        case ERROR_DISK_FULL:
        case ERROR_HANDLE_DISK_FULL: return ENOSPC;
        case ERROR_NOT_SUPPORTED:
        case ERROR_INVALID_FUNCTION: return ENOTSUP;
        case ERROR_HANDLE_EOF: return 0;
        default: return EIO;
    }
}

HANDLE handle_of(int fd) {
    const auto h = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
    if (h == INVALID_HANDLE_VALUE) errno = EBADF;
    return h;
}

bool identity_of(HANDLE h, std::uint64_t& volume, std::uint64_t& index) {
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(h, &info)) return false;
    volume = info.dwVolumeSerialNumber;
    index = (static_cast<std::uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
    return true;
}

}  // namespace

ssize_t pread(int fd, void* buf, std::size_t n, std::int64_t offset) {
    const HANDLE h = handle_of(fd);
    if (h == INVALID_HANDLE_VALUE) return -1;
    OVERLAPPED ov{};
    ov.Offset = static_cast<DWORD>(static_cast<std::uint64_t>(offset));
    ov.OffsetHigh = static_cast<DWORD>(static_cast<std::uint64_t>(offset) >> 32);
    DWORD got = 0;
    const DWORD want = n > 0x40000000u ? 0x40000000u : static_cast<DWORD>(n);
    if (!ReadFile(h, buf, want, &got, &ov)) {
        const DWORD e = GetLastError();
        if (e == ERROR_HANDLE_EOF) return 0;
        errno = errno_from_win32(e);
        return -1;
    }
    return static_cast<ssize_t>(got);
}

ssize_t pwrite(int fd, const void* buf, std::size_t n, std::int64_t offset) {
    const HANDLE h = handle_of(fd);
    if (h == INVALID_HANDLE_VALUE) return -1;
    OVERLAPPED ov{};
    ov.Offset = static_cast<DWORD>(static_cast<std::uint64_t>(offset));
    ov.OffsetHigh = static_cast<DWORD>(static_cast<std::uint64_t>(offset) >> 32);
    DWORD put = 0;
    const DWORD want = n > 0x40000000u ? 0x40000000u : static_cast<DWORD>(n);
    if (!WriteFile(h, buf, want, &put, &ov)) {
        errno = errno_from_win32(GetLastError());
        return -1;
    }
    return static_cast<ssize_t>(put);
}

int fdatasync(int fd) {
    const HANDLE h = handle_of(fd);
    if (h == INVALID_HANDLE_VALUE) return -1;
    if (!FlushFileBuffers(h)) {
        errno = errno_from_win32(GetLastError());
        return -1;
    }
    return 0;
}

int posix_fadvise(int, std::int64_t, std::int64_t, int) { return 0; }

int setenv(const char* name, const char* value, int overwrite) {
    if (!overwrite && std::getenv(name)) return 0;
    return _putenv_s(name, value) == 0 ? 0 : -1;
}

int unsetenv(const char* name) { return _putenv_s(name, "") == 0 ? 0 : -1; }

// There is no uid on Windows. A constant non-zero value: "a regular user", which is what the
// callers ask about. Whether the process may open a disk is decided by Windows at open time.
uid_t getuid() { return 1000; }

char* realpath(const char* path, char* resolved) {
    if (!_fullpath(resolved, path, PATH_MAX)) {
        errno = ENAMETOOLONG;
        return nullptr;
    }
    if (GetFileAttributesA(resolved) == INVALID_FILE_ATTRIBUTES) {
        errno = errno_from_win32(GetLastError());
        return nullptr;
    }
    return resolved;
}

ssize_t getrandom(void* buf, std::size_t n, unsigned) {
    if (BCryptGenRandom(nullptr, static_cast<PUCHAR>(buf), static_cast<ULONG>(n), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        errno = EIO;
        return -1;
    }
    return static_cast<ssize_t>(n);
}

char* mkdtemp(char* name_template) {
    if (_mktemp_s(name_template, std::strlen(name_template) + 1) != 0) return nullptr;
    return CreateDirectoryA(name_template, nullptr) ? name_template : nullptr;
}

namespace dw::win {

bool enable_ansi_console() {
    bool any = false;
    for (DWORD which : {STD_OUTPUT_HANDLE, STD_ERROR_HANDLE}) {
        const HANDLE h = GetStdHandle(which);
        DWORD mode = 0;
        if (h == INVALID_HANDLE_VALUE || !GetConsoleMode(h, &mode)) continue;
        if (SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) any = true;
    }
    return any;
}

bool read_console_secret(const char* prompt, char* out, std::size_t out_size) {
    const HANDLE in = CreateFileA("CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                  OPEN_EXISTING, 0, nullptr);
    if (in == INVALID_HANDLE_VALUE) return false;
    const HANDLE con = CreateFileA("CONOUT$", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0,
                                   nullptr);
    DWORD n = 0, old = 0;
    if (con != INVALID_HANDLE_VALUE) WriteFile(con, prompt, static_cast<DWORD>(std::strlen(prompt)), &n, nullptr);
    const bool have_mode = GetConsoleMode(in, &old) != 0;
    if (have_mode) SetConsoleMode(in, (old | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT) & ~static_cast<DWORD>(ENABLE_ECHO_INPUT));
    std::size_t len = 0;
    char c = 0;
    while (len + 1 < out_size && ReadFile(in, &c, 1, &n, nullptr) && n == 1 && c != '\n')
        if (c != '\r') out[len++] = c;
    out[len] = 0;
    if (have_mode) SetConsoleMode(in, old);
    if (con != INVALID_HANDLE_VALUE) {
        WriteFile(con, "\r\n", 2, &n, nullptr);
        CloseHandle(con);
    }
    CloseHandle(in);
    return true;
}

int open_file(const char* path, bool writable, bool unbuffered, bool device) {
    // A disk opened for reading still asks for write access: SCSI pass-through (the identify
    // commands) requires it. Nothing is written through it: the block device is read-only, and
    // pass-through on it goes through the read-only command whitelist. A write-protected disk
    // refuses write access; it is then opened for reading only, without pass-through.
    if (device && !writable) {
        const int fd = open_file(path, true, unbuffered, true);
        if (fd >= 0) return fd;
    }
    const DWORD access = GENERIC_READ | (writable ? GENERIC_WRITE : 0);
    // A writer admits readers (this process keeps its own read-only detection handle open, and
    // verification reads while the writer exists) but no second writer.
    const DWORD share = device ? FILE_SHARE_READ | FILE_SHARE_WRITE
                               : FILE_SHARE_DELETE | (writable ? FILE_SHARE_READ : (FILE_SHARE_READ | FILE_SHARE_WRITE));
    const DWORD flags = FILE_ATTRIBUTE_NORMAL | (unbuffered ? FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH : 0);
    const HANDLE h = CreateFileA(path, access, share, nullptr, OPEN_EXISTING, flags, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        errno = errno_from_win32(GetLastError());
        return -1;
    }
    const int fd = _open_osfhandle(reinterpret_cast<intptr_t>(h), (writable ? _O_RDWR : _O_RDONLY) | _O_BINARY);
    if (fd < 0) {
        CloseHandle(h);
        errno = EMFILE;
    }
    return fd;
}

bool file_identity(int fd, std::uint64_t& volume, std::uint64_t& index) {
    const HANDLE h = handle_of(fd);
    return h != INVALID_HANDLE_VALUE && identity_of(h, volume, index);
}

bool file_identity(const char* path, std::uint64_t& volume, std::uint64_t& index) {
    const HANDLE h = CreateFileA(path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                 FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    const bool ok = identity_of(h, volume, index);
    CloseHandle(h);
    return ok;
}

}  // namespace dw::win

// Files are opened in binary mode unless they ask otherwise: certificates, logs and journals
// are hashed byte for byte, so no "\n" may become "\r\n" on the way to disk.
namespace {
const int g_binary_mode = (*__p__fmode() = _O_BINARY);
}
