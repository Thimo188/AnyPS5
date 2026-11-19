# libSceIcu

## change [recovered inventory exports]

- The 134 [recovered inventory exports](../../../core/libs/prx/libSceIcu/RecoveredInventory.cpp) have unverified parameters, return types, callback ABIs and behavior. The 47 left in that file throw through `NotImplemented_nid_no_patch` as parameterless `int` placeholders; the `ubidi` and `ucsdet` ones are in [Bidi.cpp](../../../core/libs/prx/libSceIcu/Bidi.cpp) and [CharsetDetection.cpp](../../../core/libs/prx/libSceIcu/CharsetDetection.cpp). The [13.60 inventory](https://github.com/xdCloudy/PS5-13.60-Function-Stub-Library/blob/226383a7fa4b1275d6cebf61eb1c1e7ca7b58bcb/data/firmware-13.60/libsceicu-9790ee85e3.jsonl) establishes only name/NID bindings. The [module map](https://github.com/boykopovar/ps5-nid-map/blob/cc1d586fddab576a520f226da6b2632b031e6d09/data/Modules/libSceIcu.inc) assigns all 134 NIDs to logical `libSceIcu` in `libSceIcu.sprx`. Recovered `ucfpos`, `uset` and `uiter` groups are excluded. Console ABI, behavior and title compatibility remain unverified.

## add Functional

- [`ucol_countAvailable`](../../../core/libs/prx/libSceIcu/CollationAvailable.cpp) counts the installed locales in the bundled ICU collation resource index, matching ICU's fixed available-locale list rather than reporting general locales. Its name and NID identify the ICU 68 export, while the bundled implementation and data are ICU 78.1 and may differ from the console. The console ABI, data set and behavior remain unmeasured. Closes when: compared with the console.
