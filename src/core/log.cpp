#include "core/log.hpp"

#include <atomic>
#include <cstdio>
#include <ctime>
#include <mutex>

namespace dw::log {

namespace {
std::atomic<Level> g_level{Level::Info};
std::mutex g_mutex;

const char* tag(Level l) {
    switch (l) {
        case Level::Debug: return "DEBUG";
        case Level::Info: return "INFO ";
        case Level::Warn: return "WARN ";
        case Level::Error: return "ERROR";
    }
    return "?";
}
}  // namespace

void set_level(Level l) { g_level.store(l); }
Level level() { return g_level.load(); }

void write(Level l, std::string_view message) {
    timespec ts{};
    clock_gettime(CLOCK_REALTIME, &ts);
    const time_t secs = ts.tv_sec;
    tm local{};
    localtime_r(&secs, &local);
    char stamp[32];
    std::strftime(stamp, sizeof stamp, "%H:%M:%S", &local);

    std::lock_guard lock(g_mutex);
    std::fprintf(stderr, "%s.%03ld %s %.*s\n", stamp, ts.tv_nsec / 1'000'000, tag(l),
                 static_cast<int>(message.size()), message.data());
}

}  // namespace dw::log
