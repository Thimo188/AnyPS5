#include "prx/libSceIcu/Enumeration.hpp"
#include "prx/libSceIcu/RecoveredInventory.hpp"
#include "unicode/udata.h"
#include "unicode/uenum.h"
#include "uresimp.h"
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <source_location>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

static_assert(std::is_same_v<decltype(&ucol_getKeywordValues_nid_postfix),
    UEnumeration* (APS5_VABI*)(const char*, std::int32_t*)>);

namespace {

void Require(bool value, std::source_location location = std::source_location::current()) {
    if (value) return;
    std::fprintf(stderr, "ICU collation keyword check failed at line %u\n", location.line());
    std::abort();
}

template <typename Action>
void RequireInvalidArgument(Action action) {
    try {
        action();
    } catch (const std::invalid_argument&) {
        return;
    }
    Require(false);
}

struct Outcome {
    std::int32_t status;
    std::vector<std::string> values;
};

Outcome NativeValues() {
    Outcome result{};
    auto local = U_ZERO_ERROR;
    constexpr char path[] = U_ICUDATA_NAME U_TREE_SEPARATOR_STRING "coll";
    auto* enumeration = ures_getKeywordValues(path, "collations", &local);
    while (enumeration && U_SUCCESS(local)) {
        std::int32_t length = 0;
        const auto* value = uenum_next(enumeration, &length, &local);
        if (!value) break;
        result.values.emplace_back(value, static_cast<std::size_t>(length));
    }
    uenum_close(enumeration);
    result.status = local;
    return result;
}

Outcome WrappedValues() {
    Outcome result{};
    auto* enumeration = ucol_getKeywordValues_nid_postfix("collation", &result.status);
    while (enumeration && result.status <= 0) {
        std::int32_t length = 0;
        const auto* value = uenum_next_nid_postfix(enumeration, &length, &result.status);
        if (!value) break;
        result.values.emplace_back(value, static_cast<std::size_t>(length));
    }
    uenum_close_nid_postfix(enumeration);
    return result;
}

}

int main() {
    const auto expected = NativeValues();
    const auto actual = WrappedValues();
    Require(actual.status == expected.status);
    Require(actual.values == expected.values);

    constexpr const char* invalidKeywords[] = {nullptr, "", "calendar", "COLLATION", "collationx"};
    for (const auto* keyword : invalidKeywords) {
        std::int32_t status = 0;
        auto* enumeration = ucol_getKeywordValues_nid_postfix(keyword, &status);
        Require(enumeration == nullptr);
        Require(status == U_ILLEGAL_ARGUMENT_ERROR);
    }

    std::int32_t status = 1;
    Require(ucol_getKeywordValues_nid_postfix(reinterpret_cast<const char*>(0x10), &status) == nullptr);
    Require(status == 1);
    RequireInvalidArgument([&] { ucol_getKeywordValues_nid_postfix("collation", nullptr); });
    errno = 71;
    status = 0;
    RequireInvalidArgument([&] {
        ucol_getKeywordValues_nid_postfix(reinterpret_cast<const char*>(0x10), &status);
    });
    Require(errno == 71 && status == 0);
    errno = 72;
    RequireInvalidArgument([&] {
        ucol_getKeywordValues_nid_postfix("collation", reinterpret_cast<std::int32_t*>(0x10));
    });
    Require(errno == 72);
}
