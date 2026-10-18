#include "core/json.hpp"

#include <charconv>
#include <cmath>
#include <cstdio>

namespace dw {

namespace {
constexpr int kMaxDepth = 64;
}  // namespace

namespace detail {

class JsonParser {
public:
    explicit JsonParser(std::string_view s) : s_(s) {}

    Result<Json> parse_document() {
        auto v = parse_value(0);
        if (!v) return v;
        skip_ws();
        if (pos_ != s_.size()) return fail("trailing characters after JSON value");
        return v;
    }

private:
    Error fail(const std::string& what) const {
        return error("JSON parse error at offset " + std::to_string(pos_) + ": " + what);
    }

    void skip_ws() {
        while (pos_ < s_.size() && (s_[pos_] == ' ' || s_[pos_] == '\t' || s_[pos_] == '\n' || s_[pos_] == '\r'))
            ++pos_;
    }

    bool consume(std::string_view lit) {
        if (s_.substr(pos_, lit.size()) != lit) return false;
        pos_ += lit.size();
        return true;
    }

    Result<Json> parse_value(int depth) {
        if (depth > kMaxDepth) return fail("nesting too deep");
        skip_ws();
        if (pos_ >= s_.size()) return fail("unexpected end of input");
        char c = s_[pos_];
        if (c == '{') return parse_object(depth);
        if (c == '[') return parse_array(depth);
        if (c == '"') {
            auto str = parse_string();
            if (!str) return str.error();
            return Json(std::move(str).value());
        }
        if (consume("true")) return Json(true);
        if (consume("false")) return Json(false);
        if (consume("null")) return Json(nullptr);
        if (c == '-' || (c >= '0' && c <= '9')) return parse_number();
        return fail(std::string("unexpected character '") + c + "'");
    }

    Result<Json> parse_object(int depth) {
        ++pos_;  // '{'
        Json obj = Json::object();
        skip_ws();
        if (pos_ < s_.size() && s_[pos_] == '}') { ++pos_; return obj; }
        while (true) {
            skip_ws();
            if (pos_ >= s_.size() || s_[pos_] != '"') return fail("expected object key");
            auto key = parse_string();
            if (!key) return key.error();
            if (obj.find(*key)) return fail("duplicate key \"" + *key + "\"");
            skip_ws();
            if (pos_ >= s_.size() || s_[pos_] != ':') return fail("expected ':'");
            ++pos_;
            auto val = parse_value(depth + 1);
            if (!val) return val;
            obj[*key] = std::move(val).value();
            skip_ws();
            if (pos_ < s_.size() && s_[pos_] == ',') { ++pos_; continue; }
            if (pos_ < s_.size() && s_[pos_] == '}') { ++pos_; return obj; }
            return fail("expected ',' or '}'");
        }
    }

    Result<Json> parse_array(int depth) {
        ++pos_;  // '['
        Json arr = Json::array();
        skip_ws();
        if (pos_ < s_.size() && s_[pos_] == ']') { ++pos_; return arr; }
        while (true) {
            auto val = parse_value(depth + 1);
            if (!val) return val;
            arr.push_back(std::move(val).value());
            skip_ws();
            if (pos_ < s_.size() && s_[pos_] == ',') { ++pos_; continue; }
            if (pos_ < s_.size() && s_[pos_] == ']') { ++pos_; return arr; }
            return fail("expected ',' or ']'");
        }
    }

    Result<Json> parse_number() {
        // Validate the JSON number grammar, but keep the literal text.
        size_t start = pos_;
        if (s_[pos_] == '-') ++pos_;
        auto digits = [&] {
            size_t d = pos_;
            while (pos_ < s_.size() && s_[pos_] >= '0' && s_[pos_] <= '9') ++pos_;
            return pos_ - d;
        };
        if (pos_ < s_.size() && s_[pos_] == '0') {
            ++pos_;
        } else if (digits() == 0) {
            return fail("invalid number");
        }
        if (pos_ < s_.size() && s_[pos_] == '.') {
            ++pos_;
            if (digits() == 0) return fail("invalid number fraction");
        }
        if (pos_ < s_.size() && (s_[pos_] == 'e' || s_[pos_] == 'E')) {
            ++pos_;
            if (pos_ < s_.size() && (s_[pos_] == '+' || s_[pos_] == '-')) ++pos_;
            if (digits() == 0) return fail("invalid number exponent");
        }
        Json j;
        j.type_ = Json::Type::Number;
        j.text_.assign(s_.substr(start, pos_ - start));
        return j;
    }

    static void append_utf8(std::string& out, std::uint32_t cp) {
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        } else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }

    Result<std::uint32_t> parse_hex4() {
        if (pos_ + 4 > s_.size()) return fail("truncated \\u escape");
        std::uint32_t v = 0;
        auto r = std::from_chars(s_.data() + pos_, s_.data() + pos_ + 4, v, 16);
        if (r.ec != std::errc{} || r.ptr != s_.data() + pos_ + 4) return fail("invalid \\u escape");
        pos_ += 4;
        return v;
    }

    Result<std::string> parse_string() {
        ++pos_;  // opening quote
        std::string out;
        while (true) {
            if (pos_ >= s_.size()) return fail("unterminated string");
            char c = s_[pos_++];
            if (c == '"') return out;
            if (static_cast<unsigned char>(c) < 0x20) return fail("control character in string");
            if (c != '\\') { out += c; continue; }
            if (pos_ >= s_.size()) return fail("unterminated escape");
            char e = s_[pos_++];
            switch (e) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case '/': out += '/'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                case 'u': {
                    auto hi = parse_hex4();
                    if (!hi) return hi.error();
                    std::uint32_t cp = *hi;
                    if (cp >= 0xD800 && cp <= 0xDBFF) {  // surrogate pair
                        if (!consume("\\u")) return fail("unpaired high surrogate");
                        auto lo = parse_hex4();
                        if (!lo) return lo.error();
                        if (*lo < 0xDC00 || *lo > 0xDFFF) return fail("invalid low surrogate");
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (*lo - 0xDC00);
                    } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                        return fail("unpaired low surrogate");
                    }
                    append_utf8(out, cp);
                    break;
                }
                default: return fail(std::string("invalid escape '\\") + e + "'");
            }
        }
    }

    std::string_view s_;
    size_t pos_ = 0;
};

}  // namespace detail

namespace {

void escape_string(std::string& out, const std::string& s) {
    out += '"';
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", static_cast<unsigned>(static_cast<unsigned char>(c)));
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    out += '"';
}

}  // namespace

Result<Json> Json::parse(std::string_view text) { return detail::JsonParser(text).parse_document(); }

Json::Json(double d) : type_(Type::Number) {
    if (!std::isfinite(d)) {  // JSON has no NaN/Inf
        type_ = Type::Null;
        return;
    }
    char buf[32];
    auto r = std::to_chars(buf, buf + sizeof buf, d);  // shortest round-trip form
    text_.assign(buf, r.ptr);
}

const Json* Json::find(std::string_view key) const {
    if (type_ != Type::Object) return nullptr;
    for (const auto& [k, v] : object_)
        if (k == key) return &v;
    return nullptr;
}

Json& Json::operator[](std::string_view key) {
    if (type_ == Type::Null) type_ = Type::Object;
    for (auto& [k, v] : object_)
        if (k == key) return v;
    object_.emplace_back(std::string(key), Json());
    return object_.back().second;
}

void Json::push_back(Json value) {
    if (type_ == Type::Null) type_ = Type::Array;
    array_.push_back(std::move(value));
}

Result<bool> Json::as_bool() const {
    if (type_ != Type::Bool) return error("expected boolean");
    return bool_;
}

Result<std::string> Json::as_string() const {
    if (type_ != Type::String) return error("expected string");
    return text_;
}

Result<std::uint64_t> Json::as_u64() const {
    if (type_ != Type::Number) return error("expected number");
    std::uint64_t v = 0;
    auto r = std::from_chars(text_.data(), text_.data() + text_.size(), v);
    if (r.ec != std::errc{} || r.ptr != text_.data() + text_.size())
        return error("expected non-negative integer fitting in 64 bits, got " + text_);
    return v;
}

Result<std::int64_t> Json::as_i64() const {
    if (type_ != Type::Number) return error("expected number");
    std::int64_t v = 0;
    auto r = std::from_chars(text_.data(), text_.data() + text_.size(), v);
    if (r.ec != std::errc{} || r.ptr != text_.data() + text_.size())
        return error("expected integer fitting in 64 bits, got " + text_);
    return v;
}

Result<double> Json::as_double() const {
    if (type_ != Type::Number) return error("expected number");
    double v = 0;
    auto r = std::from_chars(text_.data(), text_.data() + text_.size(), v);
    if (r.ec != std::errc{}) return error("invalid number " + text_);
    return v;
}

std::string Json::dump(int indent) const {
    std::string out;
    dump_to(out, indent, 0);
    return out;
}

void Json::dump_to(std::string& out, int indent, int depth) const {
    auto newline = [&](int d) {
        if (indent < 0) return;
        out += '\n';
        out.append(static_cast<size_t>(indent * d), ' ');
    };
    switch (type_) {
        case Type::Null: out += "null"; break;
        case Type::Bool: out += bool_ ? "true" : "false"; break;
        case Type::Number: out += text_; break;
        case Type::String: escape_string(out, text_); break;
        case Type::Array:
            if (array_.empty()) { out += "[]"; break; }
            out += '[';
            for (size_t i = 0; i < array_.size(); ++i) {
                if (i) out += ',';
                newline(depth + 1);
                array_[i].dump_to(out, indent, depth + 1);
            }
            newline(depth);
            out += ']';
            break;
        case Type::Object:
            if (object_.empty()) { out += "{}"; break; }
            out += '{';
            for (size_t i = 0; i < object_.size(); ++i) {
                if (i) out += ',';
                newline(depth + 1);
                escape_string(out, object_[i].first);
                out += indent < 0 ? ":" : ": ";
                object_[i].second.dump_to(out, indent, depth + 1);
            }
            newline(depth);
            out += '}';
            break;
    }
}

}  // namespace dw
