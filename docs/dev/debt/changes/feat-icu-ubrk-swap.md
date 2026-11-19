# libSceIcu

## add Functional

- [`ubrk_swap`](../../../core/libs/prx/libSceIcu/BreakDataSwap.cpp) has no console ABI or behavior verification. Its signature and break-data transformation follow pinned ICU 68.2's [`rbbidata.cpp`](https://github.com/unicode-org/icu/blob/84e1f26ea77152936e70d53178a816dbfbf69989/icu4c/source/common/rbbidata.cpp). Guest memory is staged before the bundled backend reads or writes it, and a trusted swapper is reconstructed from the opaque handle's four public characteristics so guest-provided callback addresses are not invoked. Malformed section ranges throw instead of reproducing ICU's unchecked pointer arithmetic. Closes when: compared with the console.
