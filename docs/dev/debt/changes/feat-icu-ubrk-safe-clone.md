# libSceIcu

## add Functional

- [Versioned break iterator safe cloning](../../../core/libs/prx/libSceIcu/BreakIterator.cpp) is not compared with the console. `ubrk_safeClone_nid_postfix` follows pinned ICU 78.1 for handles supplied by the C break iterator backend in #16971, including preflight size 1, ignored caller storage, heap cloning and `U_SAFECLONE_ALLOCATED_WARNING`; status and size fields use checked guest copies. The export name identifies ICU 68, whose iterator internals and behavior may differ. Closes when: compared with the console.
