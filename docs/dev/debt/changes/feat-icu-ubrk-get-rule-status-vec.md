# libSceIcu

## add Functional

- [Versioned break rule status vectors](../../../core/libs/prx/libSceIcu/BreakIterator.cpp) are not compared with the console. `ubrk_getRuleStatusVec_nid_postfix` follows pinned ICU 78.1 for handles supplied by the C break iterator backend in #16971, while staging the vector and status through checked guest copies. The export name identifies ICU 68, whose rule data and behavior may differ. Closes when: compared with the console.
