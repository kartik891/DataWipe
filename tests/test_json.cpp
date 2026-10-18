#include "check.hpp"
#include "core/json.hpp"

using dw::Json;

int main() {
    // Round trip preserves order and exact large integers (> 2^53).
    auto j = Json::parse(R"({"b":1,"a":[true,false,null],"big":18446744073709551615,"s":"x\"y\\z\u00e9"})");
    CHECK_OK(j);
    if (j) {
        CHECK(j->dump() == R"({"b":1,"a":[true,false,null],"big":18446744073709551615,"s":"x\"y\\zé"})");
        CHECK(j->find("big")->as_u64().value() == 18446744073709551615ull);
        CHECK(j->members()[0].first == "b");
        CHECK(!j->find("s")->as_u64());
    }

    // Surrogate pair -> 4-byte UTF-8.
    auto emoji = Json::parse(R"("\ud83d\ude00")");
    CHECK_OK(emoji);
    if (emoji) CHECK(emoji->as_string().value() == "\xF0\x9F\x98\x80");

    // Rejections.
    CHECK_ERR_CONTAINS(Json::parse(R"({"a":1,"a":2})"), "duplicate key");
    CHECK_ERR_CONTAINS(Json::parse("[1,]"), "unexpected character");
    CHECK_ERR_CONTAINS(Json::parse("01"), "trailing");
    CHECK_ERR_CONTAINS(Json::parse("{} x"), "trailing");
    CHECK_ERR_CONTAINS(Json::parse("\"abc"), "unterminated");
    CHECK_ERR_CONTAINS(Json::parse(std::string(100, '[')), "too deep");
    CHECK(!Json::parse("-1")->as_u64());
    CHECK(Json::parse("-1")->as_i64().value() == -1);
    CHECK(Json::parse("1.5e3")->as_double().value() == 1500.0);

    // Building + deterministic pretty print.
    Json o = Json::object();
    o["z"] = 1;
    o["a"]["nested"] = "v";
    o["z"] = 2;  // replace keeps original position
    CHECK(o.dump() == R"({"z":2,"a":{"nested":"v"}})");
    CHECK(o.dump(2) == "{\n  \"z\": 2,\n  \"a\": {\n    \"nested\": \"v\"\n  }\n}");
    CHECK(Json(std::string("\x01")).dump() == "\"\\u0001\"");

    return finish("test_json");
}
