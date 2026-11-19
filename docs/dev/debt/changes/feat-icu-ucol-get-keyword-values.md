# libSceIcu

## add Functional

- [`ucol_getKeywordValues`](../../../core/libs/prx/libSceIcu/CollationKeywords.cpp) validates the sole ICU collation keyword and exposes the bundled ICU resource enumeration through the guest `UEnumeration` callbacks. Its name and NID identify the ICU 68 export, while the bundled implementation and data are ICU 78.1 and may differ from the console. Guest keyword and status pointers use checked access and invalid pointers throw instead of reproducing console faults. The console ABI, data set and behavior remain unmeasured. Closes when: compared with the console.
