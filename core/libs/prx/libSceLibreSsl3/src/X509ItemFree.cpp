/* Derived from LibreSSL 4.0.0 (openbsd ce488b78e0bd994780569df718596b9776ff681a)
 * https://github.com/libressl/openbsd/blob/ce488b78e0bd994780569df718596b9776ff681a/src/lib/libcrypto/pkcs7/pk7_asn1.c */
/* $OpenBSD: pk7_asn1.c,v 1.12 2015/07/25 15:33:06 jsing Exp $ */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project 2000.
 */
/* ====================================================================
 * Copyright (c) 2000 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include "prx/libSceLibreSsl3/include/Api.hpp"
#include "prx/libSceLibreSsl/include/Api.hpp"
#include "prx/libSceLibreSsl/include/OcspResponse.hpp"
#include "prx/libc/include/Api.hpp"
#include "prx/libc/include/General.hpp"
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

struct AuthorityKeyId {
    Asn1String* keyId;
    LibreSslStack* issuer;
    Asn1String* serial;
};

struct Pkcs7 {
    unsigned char* asn1;
    std::int64_t length;
    int state;
    int detached;
    LibreSslAsn1Object* type;
    void* content;
};

struct Algorithm {
    Asn1Object_nid_no_patch* algorithm;
    Asn1Type* parameter;
};

struct Attribute {
    Asn1Object_nid_no_patch* object;
    int single;
    void* value;
};

struct IssuerAndSerial {
    void* issuer;
    Asn1String* serial;
};

struct SignerInfo {
    Asn1String* version;
    IssuerAndSerial* issuerAndSerial;
    Algorithm* digestAlgorithm;
    LibreSslStack* authenticatedAttributes;
    Algorithm* digestEncryptionAlgorithm;
    Asn1String* encryptedDigest;
    LibreSslStack* unauthenticatedAttributes;
    void* key;
};

struct RecipientInfo {
    Asn1String* version;
    IssuerAndSerial* issuerAndSerial;
    Algorithm* keyEncryptionAlgorithm;
    Asn1String* encryptedKey;
    LibreSslX509* certificate;
};

struct EncryptedContent {
    Asn1Object_nid_no_patch* contentType;
    Algorithm* algorithm;
    Asn1String* encryptedData;
    const void* cipher;
};

struct SignedData {
    Asn1String* version;
    LibreSslStack* digestAlgorithms;
    LibreSslStack* certificates;
    LibreSslStack* revocations;
    LibreSslStack* signerInformation;
    Pkcs7* contents;
};

struct EnvelopedData {
    Asn1String* version;
    LibreSslStack* recipientInformation;
    EncryptedContent* encryptedContent;
};

struct SignedAndEnvelopedData {
    Asn1String* version;
    LibreSslStack* digestAlgorithms;
    LibreSslStack* certificates;
    LibreSslStack* revocations;
    LibreSslStack* signerInformation;
    EncryptedContent* encryptedContent;
    LibreSslStack* recipientInformation;
};

struct DigestData {
    Asn1String* version;
    Algorithm* digestAlgorithm;
    Pkcs7* contents;
    Asn1String* digest;
};

struct EncryptedData {
    Asn1String* version;
    EncryptedContent* encryptedContent;
};

static_assert(sizeof(Pkcs7) == 40 && offsetof(Pkcs7, type) == 24 && offsetof(Pkcs7, content) == 32);
static_assert(sizeof(Algorithm) == 16 && sizeof(Attribute) == 24 && offsetof(Attribute, value) == 16);
static_assert(sizeof(IssuerAndSerial) == 16 && sizeof(SignerInfo) == 64 && sizeof(RecipientInfo) == 40);
static_assert(sizeof(EncryptedContent) == 32 && sizeof(SignedData) == 48 && sizeof(EnvelopedData) == 24);
static_assert(sizeof(SignedAndEnvelopedData) == 56 && sizeof(DigestData) == 32 && sizeof(EncryptedData) == 16);

constexpr int Pkcs7Data = 21;
constexpr int Pkcs7Signed = 22;
constexpr int Pkcs7Enveloped = 23;
constexpr int Pkcs7SignedAndEnveloped = 24;
constexpr int Pkcs7Digest = 25;
constexpr int Pkcs7Encrypted = 26;

template<typename T>
T Read(const T* source, const char* name) {
    T value{};
    const int savedErrno = errno;
    const bool copied = GuestCopyIn_nid_no_patch(&value, source, sizeof(value));
    errno = savedErrno;
    if (!copied) throw std::invalid_argument(std::string("PKCS7_free: unreadable ") + name);
    return value;
}

int ObjectNid(const LibreSslAsn1Object* object) {
    if (!object) return 0;
    LibreSslAsn1Object value = Read(object, "content type");
    if (value.nid) return value.nid;
    if (value.length < 0) throw std::invalid_argument("PKCS7_free: negative content type length");
    std::vector<unsigned char> data(static_cast<std::size_t>(value.length));
    if (!data.empty()) {
        const int savedErrno = errno;
        const bool copied = value.data && GuestCopyIn_nid_no_patch(data.data(), value.data, data.size());
        errno = savedErrno;
        if (!copied) throw std::invalid_argument("PKCS7_free: unreadable content type data");
        value.data = data.data();
    }
    return OBJ_obj2nid_nid_postfix(&value);
}

template<typename TRelease>
void FreeStack(LibreSslStack* stack, TRelease release) {
    if (!stack) return;
    const LibreSslStack value = Read(stack, "stack");
    if (value.num < 0) throw std::invalid_argument("PKCS7_free: negative stack size");
    if (value.num && !value.data) throw std::invalid_argument("PKCS7_free: null stack data");
    for (int index = 0; index < value.num; ++index) {
        char* element = nullptr;
        const int savedErrno = errno;
        const bool copied = GuestCopyIn_nid_no_patch(&element, value.data + index, sizeof(element));
        errno = savedErrno;
        if (!copied) throw std::invalid_argument("PKCS7_free: unreadable stack data");
        release(element);
    }
    free_nid_postfix(value.data);
    free_nid_postfix(stack);
}

void FreeAlgorithm(Algorithm* algorithm) {
    if (!algorithm) return;
    const Algorithm value = Read(algorithm, "algorithm identifier");
    ASN1_TYPE_free_nid_postfix(value.parameter);
    ASN1_OBJECT_free_nid_postfix(value.algorithm);
    free_nid_postfix(algorithm);
}

void FreeAttribute(Attribute* attribute) {
    if (!attribute) return;
    const Attribute value = Read(attribute, "attribute");
    if (value.single == 0) {
        FreeStack(static_cast<LibreSslStack*>(value.value), [](void* element) {
            ASN1_TYPE_free_nid_postfix(static_cast<Asn1Type*>(element));
        });
    } else if (value.single == 1) {
        ASN1_TYPE_free_nid_postfix(static_cast<Asn1Type*>(value.value));
    }
    ASN1_OBJECT_free_nid_postfix(value.object);
    free_nid_postfix(attribute);
}

void FreeIssuerAndSerial(IssuerAndSerial* issuerAndSerial) {
    if (!issuerAndSerial) return;
    const IssuerAndSerial value = Read(issuerAndSerial, "issuer and serial");
    ASN1_INTEGER_free_nid_postfix(value.serial);
    LibreSslX509NameFree_nid_no_patch(value.issuer);
    free_nid_postfix(issuerAndSerial);
}

void FreeSignerInfo(SignerInfo* signer) {
    if (!signer) return;
    const SignerInfo value = Read(signer, "signer information");
    FreeStack(value.unauthenticatedAttributes, [](void* element) {
        FreeAttribute(static_cast<Attribute*>(element));
    });
    ASN1_OCTET_STRING_free_nid_postfix(value.encryptedDigest);
    FreeAlgorithm(value.digestEncryptionAlgorithm);
    FreeStack(value.authenticatedAttributes, [](void* element) {
        FreeAttribute(static_cast<Attribute*>(element));
    });
    FreeAlgorithm(value.digestAlgorithm);
    FreeIssuerAndSerial(value.issuerAndSerial);
    ASN1_INTEGER_free_nid_postfix(value.version);
    EVP_PKEY_free_nid_postfix(value.key);
    free_nid_postfix(signer);
}

void FreeRecipientInfo(RecipientInfo* recipient) {
    if (!recipient) return;
    const RecipientInfo value = Read(recipient, "recipient information");
    ASN1_OCTET_STRING_free_nid_postfix(value.encryptedKey);
    FreeAlgorithm(value.keyEncryptionAlgorithm);
    FreeIssuerAndSerial(value.issuerAndSerial);
    ASN1_INTEGER_free_nid_postfix(value.version);
    X509_free_nid_postfix(value.certificate);
    free_nid_postfix(recipient);
}

void FreeEncryptedContent(EncryptedContent* encrypted) {
    if (!encrypted) return;
    const EncryptedContent value = Read(encrypted, "encrypted content");
    ASN1_OCTET_STRING_free_nid_postfix(value.encryptedData);
    FreeAlgorithm(value.algorithm);
    ASN1_OBJECT_free_nid_postfix(value.contentType);
    free_nid_postfix(encrypted);
}

void FreePkcs7(Pkcs7* pkcs7);

void FreeSignedData(SignedData* signedData) {
    if (!signedData) return;
    const SignedData value = Read(signedData, "signed data");
    FreeStack(value.signerInformation, [](void* element) {
        FreeSignerInfo(static_cast<SignerInfo*>(element));
    });
    FreeStack(value.revocations, [](void* element) {
        X509_CRL_free_nid_postfix(static_cast<LibreSsl3X509Crl*>(element));
    });
    FreeStack(value.certificates, [](void* element) {
        X509_free_nid_postfix(static_cast<LibreSslX509*>(element));
    });
    FreePkcs7(value.contents);
    FreeStack(value.digestAlgorithms, [](void* element) {
        FreeAlgorithm(static_cast<Algorithm*>(element));
    });
    ASN1_INTEGER_free_nid_postfix(value.version);
    free_nid_postfix(signedData);
}

void FreeEnvelopedData(EnvelopedData* enveloped) {
    if (!enveloped) return;
    const EnvelopedData value = Read(enveloped, "enveloped data");
    FreeEncryptedContent(value.encryptedContent);
    FreeStack(value.recipientInformation, [](void* element) {
        FreeRecipientInfo(static_cast<RecipientInfo*>(element));
    });
    ASN1_INTEGER_free_nid_postfix(value.version);
    free_nid_postfix(enveloped);
}

void FreeSignedAndEnvelopedData(SignedAndEnvelopedData* signedAndEnveloped) {
    if (!signedAndEnveloped) return;
    const SignedAndEnvelopedData value = Read(signedAndEnveloped, "signed and enveloped data");
    FreeStack(value.signerInformation, [](void* element) {
        FreeSignerInfo(static_cast<SignerInfo*>(element));
    });
    FreeStack(value.revocations, [](void* element) {
        X509_CRL_free_nid_postfix(static_cast<LibreSsl3X509Crl*>(element));
    });
    FreeStack(value.certificates, [](void* element) {
        X509_free_nid_postfix(static_cast<LibreSslX509*>(element));
    });
    FreeEncryptedContent(value.encryptedContent);
    FreeStack(value.digestAlgorithms, [](void* element) {
        FreeAlgorithm(static_cast<Algorithm*>(element));
    });
    FreeStack(value.recipientInformation, [](void* element) {
        FreeRecipientInfo(static_cast<RecipientInfo*>(element));
    });
    ASN1_INTEGER_free_nid_postfix(value.version);
    free_nid_postfix(signedAndEnveloped);
}

void FreeDigestData(DigestData* digest) {
    if (!digest) return;
    const DigestData value = Read(digest, "digest data");
    ASN1_OCTET_STRING_free_nid_postfix(value.digest);
    FreePkcs7(value.contents);
    FreeAlgorithm(value.digestAlgorithm);
    ASN1_INTEGER_free_nid_postfix(value.version);
    free_nid_postfix(digest);
}

void FreeEncryptedData(EncryptedData* encrypted) {
    if (!encrypted) return;
    const EncryptedData value = Read(encrypted, "encrypted data");
    FreeEncryptedContent(value.encryptedContent);
    ASN1_INTEGER_free_nid_postfix(value.version);
    free_nid_postfix(encrypted);
}

void FreePkcs7(Pkcs7* pkcs7) {
    if (!pkcs7) return;
    const Pkcs7 value = Read(pkcs7, "object");
    switch (ObjectNid(value.type)) {
    case Pkcs7Data:
        ASN1_OCTET_STRING_free_nid_postfix(static_cast<Asn1String*>(value.content));
        break;
    case Pkcs7Signed:
        FreeSignedData(static_cast<SignedData*>(value.content));
        break;
    case Pkcs7Enveloped:
        FreeEnvelopedData(static_cast<EnvelopedData*>(value.content));
        break;
    case Pkcs7SignedAndEnveloped:
        FreeSignedAndEnvelopedData(static_cast<SignedAndEnvelopedData*>(value.content));
        break;
    case Pkcs7Digest:
        FreeDigestData(static_cast<DigestData*>(value.content));
        break;
    case Pkcs7Encrypted:
        FreeEncryptedData(static_cast<EncryptedData*>(value.content));
        break;
    default:
        ASN1_TYPE_free_nid_postfix(static_cast<Asn1Type*>(value.content));
        break;
    }
    ASN1_OBJECT_free_nid_postfix(reinterpret_cast<Asn1Object_nid_no_patch*>(value.type));
    free_nid_postfix(pkcs7);
}

static_assert(sizeof(AuthorityKeyId) == 24 && offsetof(AuthorityKeyId, serial) == 16);

AuthorityKeyId ReadAuthorityKeyId(const void* source) {
    AuthorityKeyId value{};
    const int savedErrno = errno;
    const bool copied = GuestCopyIn_nid_no_patch(&value, source, sizeof(value));
    errno = savedErrno;
    if (!copied) throw std::invalid_argument(std::string(__func__) + ": unreadable authority key identifier");
    return value;
}

}

extern "C" {

void APS5_VABI AUTHORITY_KEYID_free_nid_postfix(void* authorityKeyId) {
    if (!authorityKeyId) return;
    const AuthorityKeyId value = ReadAuthorityKeyId(authorityKeyId);
    ASN1_OCTET_STRING_free_nid_postfix(value.keyId);
    GENERAL_NAMES_free_nid_postfix(value.issuer);
    ASN1_INTEGER_free_nid_postfix(value.serial);
    free_nid_postfix(authorityKeyId);
}

void APS5_VABI PKCS7_free_nid_postfix(void* pkcs7) {
    FreePkcs7(static_cast<Pkcs7*>(pkcs7));
}

}
