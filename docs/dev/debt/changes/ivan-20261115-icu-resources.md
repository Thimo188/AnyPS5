# libSceIcu

## change [ICU resource bundle exports]

- [Resource-bundle reads](../../../core/libs/prx/libSceIcu/ResourceBundle.cpp) lack console ABI/data-version/default/path parity. Fifteen calls use pinned [ICU 78.1](https://github.com/unicode-org/icu/blob/049e0d6a420629ac7db77256987d083a563287b5/icu4c/source/common/uresbund.cpp); `ures_getVersionNumber` matches ICU 68.2 and returns a bundle-owned cached `Version` or `0`. Caller-allocated `fillIn` and NULL locale IDs throw. Missing locales may use host defaults; title paths/packages are unverified. NULL-status opens return no object instead of native dereference. Overlapping length/status outputs are unverified. Borrowed data must not race close/reuse/cleanup. Native bundles close, but tokens persist. Cleanup/reconfiguration require no live/concurrent objects. Other APIs and unusable guest memory throw. Closes when: console ABI, data, defaults, paths, layouts and remaining APIs are verified or implemented.
