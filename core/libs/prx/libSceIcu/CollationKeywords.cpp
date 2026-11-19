#include "prx/libSceIcu/HostEnumeration.hpp"
#include "prx/libSceIcu/RecoveredInventory.hpp"
#include "prx/libc/include/General.hpp"
#include "unicode/udata.h"
#include "uresimp.h"
#include <cerrno>
#include <cstdint>
#include <new>
#include <stdexcept>
#include <string>

extern "C" {

UEnumeration* APS5_VABI ucol_getKeywordValues_nid_postfix(const char* keyword, std::int32_t* status) {
    return Icu::OpenHostEnumeration(status, [keyword](UErrorCode* local) {
        if (!keyword) {
            *local = U_ILLEGAL_ARGUMENT_ERROR;
            return static_cast<UEnumeration*>(nullptr);
        }
        std::string text;
        const int savedErrno = errno;
        const int copied = CopyGuestString_nid_no_patch(keyword, 10, text);
        errno = savedErrno;
        if (copied == 12) throw std::bad_alloc();
        if (copied == 14) throw std::invalid_argument("ucol_getKeywordValues_nid_postfix: unreadable keyword");
        if (copied != 0 || text != "collation") {
            *local = U_ILLEGAL_ARGUMENT_ERROR;
            return static_cast<UEnumeration*>(nullptr);
        }
        constexpr char path[] = U_ICUDATA_NAME U_TREE_SEPARATOR_STRING "coll";
        return ures_getKeywordValues(path, "collations", local);
    }, __func__);
}

}
