# libSceIcu

## add Functional

- [`ucnv_getDefaultName`](../../../core/libs/prx/libSceIcu/ConverterHelpers.cpp) follows ICU 68.2 and the bundled ICU 78.1 by returning their library-owned default-converter name. Linux and macOS build ICU with `U_CHARSET_IS_UTF8=1`, so the pointer names `UTF-8` for the process lifetime and ignores locale environment changes. Other builds use ICU's mutex-protected, canonicalized platform code-page cache. The name state is the one used by `u_getDefaultConverter`, `u_releaseDefaultConverter` and `u_flushDefaultConverter`; flushing converter objects does not invalidate the name. The console's build-time charset setting and default encoding are unverified. Closes when: compared with the console.
