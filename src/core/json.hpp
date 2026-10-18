#pragma once
// Small JSON value + parser + serializer.
//
// Design choices (deliberate, not shortcuts):
//  * Numbers are stored as their source text. Sector counts and byte offsets are uint64 and
//    routinely exceed 2^53, which a double cannot hold exactly; we only convert on access.
//  * Objects keep insertion order. The certificate stub (Phase 4) hashes the serialized
//    record, so serialization must be deterministic.
//  * Duplicate keys are rejected on parse rather than silently picking one.

#include <concepts>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/result.hpp"

namespace dw {

namespace detail { class JsonParser; }

class Json {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };
    using Array = std::vector<Json>;
    using Object = std::vector<std::pair<std::string, Json>>;

    Json() = default;
    Json(std::nullptr_t) {}
    Json(bool b) : type_(Type::Bool), bool_(b) {}
    Json(std::string s) : type_(Type::String), text_(std::move(s)) {}
    Json(std::string_view s) : Json(std::string(s)) {}
    Json(const char* s) : Json(std::string(s)) {}
    template <std::integral I>
        requires(!std::same_as<I, bool>)
    Json(I n) : type_(Type::Number), text_(std::to_string(n)) {}
    Json(double d);

    static Json array() { Json j; j.type_ = Type::Array; return j; }
    static Json object() { Json j; j.type_ = Type::Object; return j; }

    static Result<Json> parse(std::string_view text);
    // indent < 0: compact single line. indent >= 0: pretty-printed with that many spaces.
    std::string dump(int indent = -1) const;

    Type type() const { return type_; }
    bool is_null() const { return type_ == Type::Null; }
    bool is_bool() const { return type_ == Type::Bool; }
    bool is_number() const { return type_ == Type::Number; }
    bool is_string() const { return type_ == Type::String; }
    bool is_array() const { return type_ == Type::Array; }
    bool is_object() const { return type_ == Type::Object; }

    // Object access. find() returns nullptr if missing or not an object.
    const Json* find(std::string_view key) const;
    // Insert-or-replace; converts a Null value into an Object on first use.
    Json& operator[](std::string_view key);
    void push_back(Json value);

    const Array& items() const { return array_; }
    const Object& members() const { return object_; }

    // Typed accessors with error reporting (used for schema validation of profile files).
    Result<bool> as_bool() const;
    Result<std::string> as_string() const;
    Result<std::uint64_t> as_u64() const;
    Result<std::int64_t> as_i64() const;
    Result<double> as_double() const;

private:
    friend class detail::JsonParser;
    void dump_to(std::string& out, int indent, int depth) const;

    Type type_ = Type::Null;
    bool bool_ = false;
    std::string text_;  // string payload, or number literal text
    Array array_;
    Object object_;
};

}  // namespace dw
