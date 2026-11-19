# libSceLibreSsl3

## remove `X509_check_akid`

## add Functional

- [X509_check_akid](../../../core/libs/prx/libSceLibreSsl3/src/X509ItemFree.cpp) - not measured on a PS5. Key identifier, signed serial number and first directory-name matching follow LibreSSL 4.0.0 [`X509_check_akid`](https://github.com/libressl/openbsd/blob/ce488b78e0bd994780569df718596b9776ff681a/src/lib/libcrypto/x509/x509_purp.c#L853-L890), including its check order and result codes. The 104-byte cached-extension certificate prefix follows that pinned LP64 layout and is not measured on the console. Directory names compare their existing canonical encodings; a modified name or one without a canonical encoding throws because canonical `X509_NAME` encoding is not exposed by either reimplemented library. Closes when: compared with the console and canonical name regeneration is implemented.
