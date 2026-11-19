# libSceIcu

## change [ICU resource bundle exports]

- [ICU resource bundle exports](../../../core/libs/prx/libSceIcu/ResourceBundle.cpp) implement only the early returns of ICU 68.2 ([uresbund.cpp](https://github.com/unicode-org/icu/blob/84e1f26ea77152936e70d53178a816dbfbf69989/icu4c/source/common/uresbund.cpp): `ures_close` 924-945). A null handle returns without action. Closing a non-null handle and every path that needs resource data throw `NotImplemented_nid_no_patch`. `ures_resetIterator` follows the ICU 68.2 200-byte `UResourceBundle` ABI and stores -1 at its iterator index at byte 188; a null handle is a no-op and inaccessible guest storage throws. The layout and behavior are unverified on a console. Closes when: the remaining resource bundle exports are implemented and compared with the console.
