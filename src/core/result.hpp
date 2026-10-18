#pragma once
// Minimal Expected-style error channel. std::expected is C++23; this keeps us on C++20
// and makes every failure path explicit at the call site (no exceptions on the I/O path).

#include <cerrno>
#include <cstring>
#include <string>
#include <utility>
#include <variant>

namespace dw {

struct Error {
    std::string message;
    int sys_errno = 0;  // 0 when the failure is not a syscall failure

    std::string describe() const {
        if (sys_errno == 0) return message;
        return message + ": " + std::strerror(sys_errno) + " (errno " + std::to_string(sys_errno) + ")";
    }
};

// Capture errno immediately after a failed syscall: `return sys_error("open " + path);`
inline Error sys_error(std::string context, int err = errno) { return Error{std::move(context), err}; }
inline Error error(std::string message) { return Error{std::move(message), 0}; }

template <typename T>
class [[nodiscard]] Result {
public:
    Result(T value) : v_(std::move(value)) {}
    Result(Error err) : v_(std::move(err)) {}

    bool ok() const { return std::holds_alternative<T>(v_); }
    explicit operator bool() const { return ok(); }

    T& value() & { return std::get<T>(v_); }
    const T& value() const& { return std::get<T>(v_); }
    T&& value() && { return std::get<T>(std::move(v_)); }
    T* operator->() { return &value(); }
    const T* operator->() const { return &value(); }
    T& operator*() & { return value(); }
    const T& operator*() const& { return value(); }

    const Error& error() const { return std::get<Error>(v_); }

private:
    std::variant<T, Error> v_;
};

template <>
class [[nodiscard]] Result<void> {
public:
    Result() = default;
    Result(Error err) : err_(std::move(err)), ok_(false) {}

    bool ok() const { return ok_; }
    explicit operator bool() const { return ok_; }
    const Error& error() const { return err_; }

private:
    Error err_;
    bool ok_ = true;
};

inline Result<void> ok() { return {}; }

}  // namespace dw
