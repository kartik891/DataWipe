#pragma once
// Minimal test harness: CHECK records failures and continues; main returns the failure count.

#include <cstdio>
#include <string>

inline int g_failures = 0;

#define CHECK(cond)                                                                   \
    do {                                                                              \
        if (!(cond)) {                                                                \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
            ++g_failures;                                                             \
        }                                                                             \
    } while (0)

// For Result<T>. Each macro evaluates its argument exactly once.
#define CHECK_OK(res)                                                                          \
    do {                                                                                       \
        const auto& dw_r_ = (res);                                                             \
        if (!dw_r_) {                                                                          \
            std::fprintf(stderr, "FAIL %s:%d: %s -> %s\n", __FILE__, __LINE__, #res,           \
                         dw_r_.error().describe().c_str());                                    \
            ++g_failures;                                                                      \
        }                                                                                      \
    } while (0)

#define CHECK_ERR_CONTAINS(res, needle)                                                         \
    do {                                                                                        \
        const auto& dw_r_ = (res);                                                              \
        if (dw_r_) {                                                                            \
            std::fprintf(stderr, "FAIL %s:%d: %s unexpectedly succeeded\n", __FILE__, __LINE__, #res); \
            ++g_failures;                                                                       \
        } else if (dw_r_.error().describe().find(needle) == std::string::npos) {                \
            std::fprintf(stderr, "FAIL %s:%d: %s error '%s' lacks '%s'\n", __FILE__, __LINE__, #res, \
                         dw_r_.error().describe().c_str(), needle);                             \
            ++g_failures;                                                                       \
        }                                                                                       \
    } while (0)

inline int finish(const char* name) {
    if (g_failures == 0) std::fprintf(stderr, "%s: all checks passed\n", name);
    else std::fprintf(stderr, "%s: %d check(s) FAILED\n", name, g_failures);
    return g_failures == 0 ? 0 : 1;
}
