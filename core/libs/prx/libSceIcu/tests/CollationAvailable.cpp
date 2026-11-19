#include "prx/libSceIcu/RecoveredInventory.hpp"
#include "unicode/udata.h"
#include "unicode/ures.h"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <source_location>
#include <string>
#include <type_traits>
#include <vector>

static_assert(std::is_same_v<decltype(&ucol_countAvailable_nid_postfix), std::int32_t (APS5_VABI*)()>);
static_assert(std::is_same_v<decltype(&ucol_getAvailable_nid_postfix), const char* (APS5_VABI*)(std::int32_t)>);

namespace {

void Require(bool value, std::source_location location = std::source_location::current()) {
    if (value) return;
    std::fprintf(stderr, "ICU collation availability check failed at line %u\n", location.line());
    std::abort();
}

std::vector<std::string> ResourceLocales() {
    std::vector<std::string> result;
    constexpr char path[] = U_ICUDATA_NAME U_TREE_SEPARATOR_STRING "coll";
    UErrorCode status = U_ZERO_ERROR;
    auto* index = ures_openDirect(path, "res_index", &status);
    UResourceBundle* installed = nullptr;
    if (U_SUCCESS(status)) installed = ures_getByKey(index, "InstalledLocales", nullptr, &status);
    if (U_SUCCESS(status)) {
        result.reserve(static_cast<std::size_t>(ures_getSize(installed)));
        ures_resetIterator(installed);
        while (ures_hasNext(installed)) {
            const char* key = nullptr;
            ures_getNextString(installed, nullptr, &key, &status);
            if (U_FAILURE(status) || !key) {
                result.clear();
                break;
            }
            result.emplace_back(key);
        }
    }
    ures_close(installed);
    ures_close(index);
    return result;
}

}

int main() {
    const auto expected = ResourceLocales();
    Require(ucol_countAvailable_nid_postfix() == static_cast<std::int32_t>(expected.size()));
    for (std::size_t index = 0; index < expected.size(); ++index) {
        const auto* first = ucol_getAvailable_nid_postfix(static_cast<std::int32_t>(index));
        const auto* second = ucol_getAvailable_nid_postfix(static_cast<std::int32_t>(index));
        Require(first && second == first && expected[index] == first);
    }
    Require(ucol_getAvailable_nid_postfix(-1) == nullptr);
    Require(ucol_getAvailable_nid_postfix(static_cast<std::int32_t>(expected.size())) == nullptr);
    Require(ucol_getAvailable_nid_postfix((std::numeric_limits<std::int32_t>::max)()) == nullptr);
}
