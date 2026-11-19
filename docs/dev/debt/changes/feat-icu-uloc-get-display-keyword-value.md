# libSceIcu

## add Functional

- [`uloc_getDisplayKeywordValue`](../../../core/libs/prx/libSceIcu/LocaleDisplay.cpp) follows the bundled ICU public C API and available locale data. Its name and NID identify the ICU 68 export, while the bundled implementation and data are ICU 78.1 and may differ from the console. Null locale arguments use AnyPS5's configured default locale instead of host-global ICU state. Guest strings, output and status are copied through checked access; invalid pointers and the upstream undefined null-keyword case throw instead of reproducing console faults. The console ABI and behavior remain unmeasured. Closes when: compared with the console.
