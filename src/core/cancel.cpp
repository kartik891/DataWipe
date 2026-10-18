#include "core/cancel.hpp"

#include <signal.h>
#include <unistd.h>

#include <initializer_list>

namespace dw {

namespace {

CancelToken* g_token = nullptr;

extern "C" void on_signal(int) {
    // Only async-signal-safe operations: a lock-free atomic store and write(2).
    if (g_token) g_token->request();
    static constexpr char kMsg[] =
        "\ninterrupt: stopping at the next chunk boundary and saving progress "
        "(interrupt again to kill immediately)\n";
    [[maybe_unused]] auto n = ::write(STDERR_FILENO, kMsg, sizeof kMsg - 1);
}

}  // namespace

#ifdef _WIN32
// Ctrl-C and Ctrl-Break. The C runtime resets the handler after one delivery, which is the
// one-shot behaviour wanted: a second Ctrl-C ends the process.
void install_cancel_signal_handlers(CancelToken& token) {
    g_token = &token;
    for (int sig : {SIGINT, SIGTERM, SIGBREAK}) ::signal(sig, on_signal);
}

void clear_cancel_signal_handlers() {
    for (int sig : {SIGINT, SIGTERM, SIGBREAK}) ::signal(sig, SIG_DFL);
    g_token = nullptr;
}
#else
void install_cancel_signal_handlers(CancelToken& token) {
    g_token = &token;
    struct sigaction sa{};
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESETHAND | SA_RESTART;  // one-shot; don't turn in-flight syscalls into EINTR
    for (int sig : {SIGINT, SIGTERM, SIGHUP}) ::sigaction(sig, &sa, nullptr);
}

void clear_cancel_signal_handlers() {
    for (int sig : {SIGINT, SIGTERM, SIGHUP}) ::signal(sig, SIG_DFL);
    g_token = nullptr;
}
#endif

}  // namespace dw
