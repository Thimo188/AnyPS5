# libSceIcu

## add Functional

- [`ucol_getAvailable`](../../../core/libs/prx/libSceIcu/CollationAvailable.cpp) returns stable locale identifiers from the bundled ICU collation resource index and rejects out-of-range indices with a null result. Its name and NID identify the ICU 68 export, while the bundled implementation and data are ICU 78.1 and may differ from the console. ICU leaves negative indices undefined; this wrapper returns null instead of indexing before the locale array. The console ABI, data set and behavior remain unmeasured. Closes when: compared with the console.
