# libSceLibreSsl3

## add Functional

- [`d2i_PKCS7`](../../../core/libs/prx/libSceLibreSsl3/src/Pkcs7Decode.cpp) - not measured on a PS5. The recovered LP64 ABI and object graph follow LibreSSL 4.0.0 [`d2i_PKCS7`](https://github.com/libressl/openbsd/blob/ce488b78e0bd994780569df718596b9776ff681a/src/lib/libcrypto/pkcs7/pk7_asn1.c#L242-L246), including all six classic PKCS7 content choices, the default ANY choice, replacement ownership and input-cursor advancement. It accepts definite-length DER. Indefinite lengths and high-tag-number values throw rather than invent behaviour; other BER forms fail with an ASN.1 error. Firmware error-stack ordering and output/input alias precedence have not been observed.
