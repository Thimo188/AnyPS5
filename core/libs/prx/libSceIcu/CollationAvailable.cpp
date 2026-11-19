#include "prx/libSceIcu/RecoveredInventory.hpp"
#include "unicode/udata.h"
#include "unicode/ures.h"
#include <cstdint>

extern "C" {

std::int32_t APS5_VABI ucol_countAvailable_nid_postfix() {
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
