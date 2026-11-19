#include "prx/libSceIcu/RecoveredInventory.hpp"
#include "unicode/udata.h"
#include "unicode/ures.h"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <source_location>
#include <type_traits>

static_assert(std::is_same_v<decltype(&ucol_countAvailable_nid_postfix), std::int32_t (APS5_VABI*)()>);

namespace {

void Require(bool value, std::source_location location = std::source_location::current()) {
    if (value) return;
    std::fprintf(stderr, "ICU collation availability check failed at line %u\n", location.line());
    std::abort();
}

std::int32_t ResourceCount() {
    constexpr char path[] = U_ICUDATA_NAME U_TREE_SEPARATOR_STRING "coll";
    UErrorCode status = U_ZERO_ERROR;
    auto* index = ures_openDirect(path, "res_index", &status);
    UResourceBundle* installed = nullptr;
    if (U_SUCCESS(status)) installed = ures_getByKey(index, "InstalledLocales", nullptr, &status);
    const auto count = U_SUCCESS(status) ? ures_getSize(installed) : 0;
    ures_close(installed);
    ures_close(index);
    return count;
}

}

int main() {
    const auto expected = ResourceCount();
    Require(expected >= 0);
    Require(ucol_countAvailable_nid_postfix() == expected);
    Require(ucol_countAvailable_nid_postfix() == expected);
}
