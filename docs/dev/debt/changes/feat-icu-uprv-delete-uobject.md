# libSceIcu

## add Functional

- [`uprv_deleteUObject`](../../../core/libs/prx/libSceIcu/Object.cpp) deletes null or valid bundled-ICU `UObject` instances through the pinned ICU 78.1 virtual destructor and allocator. Its name and NID identify the ICU 68 export, so object layout compatibility and console behavior remain unmeasured. Closes when: compared with the console.
