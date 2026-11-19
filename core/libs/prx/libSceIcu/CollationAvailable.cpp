#include "prx/libSceIcu/RecoveredInventory.hpp"
#include "unicode/udata.h"
#include "unicode/ures.h"
#include <cstdint>
#include <string>
#include <vector>

namespace {

const std::vector<std::string>& AvailableLocales() {
    static const auto locales = [] {
        std::vector<std::string> result;
        constexpr char path[] = U_ICUDATA_NAME U_TREE_SEPARATOR_STRING "coll";
        UErrorCode status = U_ZERO_ERROR;
        auto* index = ures_openDirect(path, "res_index", &status);
        UResourceBundle* installed = nullptr;
        if (U_SUCCESS(status)) installed = ures_getByKey(index, "InstalledLocales", nullptr, &status);
        if (U_SUCCESS(status)) {
            const auto count = ures_getSize(installed);
            result.reserve(static_cast<std::size_t>(count));
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
    }();
    return locales;
}

}

extern "C" {

std::int32_t APS5_VABI ucol_countAvailable_nid_postfix() {
    return static_cast<std::int32_t>(AvailableLocales().size());
}

const char* APS5_VABI ucol_getAvailable_nid_postfix(std::int32_t index) {
    const auto& locales = AvailableLocales();
    if (index < 0 || static_cast<std::size_t>(index) >= locales.size()) return nullptr;
    return locales[static_cast<std::size_t>(index)].c_str();
}

}
