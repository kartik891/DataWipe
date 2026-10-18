#pragma once
// Windows build only (force-included by CMake): the handful of POSIX calls the portable code
// uses that MinGW-w64 does not provide, implemented in win_compat.cpp on the Win32 API.
// Everything here keeps POSIX semantics (return -1 and set errno), so call sites stay as they are.
#ifdef _WIN32
#ifdef __cplusplus

#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <climits>
#include <cstddef>
#include <cstdint>
#include <ctime>

#define O_CLOEXEC O_NOINHERIT
#define O_NOFOLLOW 0
#define O_NONBLOCK 0
// No open(2) flag does this on Windows: unbuffered handles come from dw::win::open_file().
#define O_DIRECT 0
#define POSIX_FADV_DONTNEED 4

using uid_t = unsigned;

// Positional I/O on the Win32 handle behind fd; the file position is not used or moved.
ssize_t pread(int fd, void* buf, std::size_t n, std::int64_t offset);
ssize_t pwrite(int fd, const void* buf, std::size_t n, std::int64_t offset);
int fdatasync(int fd);  // FlushFileBuffers: file data and, on a disk handle, the drive's write cache
// The Windows cache cannot be told to drop a range; succeeds without doing anything. Reads
// that must come from the medium use an unbuffered handle instead (--direct).
int posix_fadvise(int fd, std::int64_t offset, std::int64_t len, int advice);
int setenv(const char* name, const char* value, int overwrite);
int unsetenv(const char* name);
uid_t getuid();
char* realpath(const char* path, char* resolved);  // resolved must hold PATH_MAX bytes
ssize_t getrandom(void* buf, std::size_t n, unsigned flags);

inline int fsync(int fd) { return fdatasync(fd); }
// The C runtime's write() takes an unsigned count; this is the size_t form POSIX has.
inline ssize_t write(int fd, const void* buf, std::size_t n) {
    return ::_write(fd, buf, n > INT_MAX ? static_cast<unsigned>(INT_MAX) : static_cast<unsigned>(n));
}
inline tm* localtime_r(const time_t* t, tm* out) { return ::localtime_s(out, t) == 0 ? out : nullptr; }
inline tm* gmtime_r(const time_t* t, tm* out) { return ::gmtime_s(out, t) == 0 ? out : nullptr; }

// Linux block-layer ioctl numbers. They only name commands in plans and logs here: nothing on
// Windows can issue them.
#define BLKDISCARD 0x1277
#define BLKSECDISCARD 0x127D

char* mkdtemp(char* name_template);  // tests

namespace dw::win {

// Switch the console to ANSI escape processing (colour, in-place progress line). False on a
// console too old for it, or when output is not a console.
bool enable_ansi_console();

// Read a line from the console with echo off, whatever stdin is redirected to. Empty if there
// is no console.
bool read_console_secret(const char* prompt, char* out, std::size_t out_size);

// CreateFile wrapped in a C runtime fd. `unbuffered` = FILE_FLAG_NO_BUFFERING | WRITE_THROUGH
// (the O_DIRECT equivalent: sector-aligned I/O straight to the medium). A writable file admits
// readers but no other writer while it is being overwritten. A disk (`device`) is opened with
// the sharing Windows requires for disks; nothing else can have a volume on it by then (the
// safety guard refused it otherwise). A disk opened for reading is opened with write access
// when Windows allows it, because SCSI pass-through needs it (see win_compat.cpp).
int open_file(const char* path, bool writable, bool unbuffered, bool device = false);

// Volume serial number and file index: what st_dev/st_ino are on POSIX. False on failure.
bool file_identity(int fd, std::uint64_t& volume, std::uint64_t& index);
bool file_identity(const char* path, std::uint64_t& volume, std::uint64_t& index);

}  // namespace dw::win

#endif  // __cplusplus
#endif  // _WIN32
