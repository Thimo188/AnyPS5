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
#include "prx/libSceLibreSsl/include/Error.hpp"
#include "prx/libSceLibreSsl/include/OcspResponse.hpp"
#include "prx/libc/include/Api.hpp"
#include "prx/libc/include/General.hpp"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

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
static_assert(sizeof(Algorithm) == 16 && sizeof(Attribute) == 24 && sizeof(IssuerAndSerial) == 16);
static_assert(sizeof(SignerInfo) == 64 && sizeof(RecipientInfo) == 40 && sizeof(EncryptedContent) == 32);
static_assert(sizeof(SignedData) == 48 && sizeof(EnvelopedData) == 24 && sizeof(SignedAndEnvelopedData) == 56);
static_assert(sizeof(DigestData) == 32 && sizeof(EncryptedData) == 16);

constexpr int Asn1Library = 13;
constexpr int AnyFunction = 0xfff;
constexpr int LengthMismatch = 62;
constexpr int MallocFailure = 65;
constexpr int BadObjectHeader = 102;
constexpr int FieldMissing = 121;
constexpr int SequenceLengthMismatch = 148;
constexpr int SequenceNotConstructed = 149;
constexpr int TooLong = 155;
constexpr int WrongTag = 168;
constexpr int InvalidObjectEncoding = 216;
constexpr int InvalidBitStringBitsLeft = 220;

constexpr int Pkcs7Data = 21;
constexpr int Pkcs7Signed = 22;
constexpr int Pkcs7Enveloped = 23;
constexpr int Pkcs7SignedAndEnveloped = 24;
constexpr int Pkcs7Digest = 25;
constexpr int Pkcs7Encrypted = 26;

constexpr int ObjectDynamic = 0x01;
constexpr int ObjectDynamicData = 0x08;
constexpr std::int64_t BitsLeftFlag = 0x08;

constexpr unsigned char IntegerTag = 0x02;
constexpr unsigned char BooleanTag = 0x01;
constexpr unsigned char BitStringTag = 0x03;
constexpr unsigned char OctetStringTag = 0x04;
constexpr unsigned char NullTag = 0x05;
constexpr unsigned char ObjectTag = 0x06;
constexpr unsigned char SequenceTag = 0x30;
constexpr unsigned char SetTag = 0x31;
constexpr unsigned char ExplicitContentTag = 0xa0;
constexpr unsigned char CertificatesTag = 0xa0;
constexpr unsigned char RevocationsTag = 0xa1;
constexpr unsigned char ImplicitOctetStringTag = 0x80;

constexpr int NameStringTags[] = {12, 18, 19, 20, 21, 22, 26, 27, 28, 30};

void PutError(int reason) {
    LibreSslPutError_nid_no_patch(Asn1Library, AnyFunction, reason);
}

struct Tlv {
    unsigned char tag;
    std::span<const unsigned char> content;
    std::span<const unsigned char> encoded;
};

bool ReadTlv(std::span<const unsigned char>& input, Tlv& value) {
    if (input.size() < 2) {
        PutError(BadObjectHeader);
        return false;
    }
    if ((input[0] & 0x1f) == 0x1f) NotImplemented_nid_no_patch("d2i_PKCS7 high-tag-number form");
    std::size_t offset = 2;
    std::size_t length = input[1];
    if (length == 0x80) NotImplemented_nid_no_patch("d2i_PKCS7 indefinite-length BER");
    if (length & 0x80) {
        const std::size_t count = length & 0x7f;
        if (count == 0 || count > sizeof(std::size_t) || input.size() < 2 + count || input[2] == 0) {
            PutError(BadObjectHeader);
            return false;
        }
        length = 0;
        for (std::size_t index = 0; index < count; ++index) {
            if (length > (std::numeric_limits<std::size_t>::max() >> 8)) {
                PutError(BadObjectHeader);
                return false;
            }
            length = (length << 8) | input[2 + index];
        }
        if (length < 128) {
            PutError(BadObjectHeader);
            return false;
        }
        offset += count;
    }
    if (length > input.size() - offset) {
        PutError(TooLong);
        return false;
    }
    value = {input[0], input.subspan(offset, length), input.first(offset + length)};
    input = input.subspan(offset + length);
    return true;
}

bool Next(std::span<const unsigned char>& input, unsigned char tag, Tlv& value) {
    if (!ReadTlv(input, value)) return false;
    if (value.tag == tag) return true;
    PutError(tag == SequenceTag && (value.tag & 0x1f) == 0x10 && !(value.tag & 0x20) ? SequenceNotConstructed : WrongTag);
    return false;
}

template<typename T>
T* NewValue() {
    auto* value = static_cast<T*>(calloc_nid_postfix(1, sizeof(T)));
    if (!value) PutError(MallocFailure);
    return value;
}

bool IsObjectEncoding(std::span<const unsigned char> content) {
    if (content.empty()) return false;
    std::size_t index = 0;
    while (index < content.size()) {
        bool first = true;
        for (;;) {
            if (index == content.size()) return false;
            const unsigned char byte = content[index++];
            if (first && byte == 0x80) return false;
            first = false;
            if (!(byte & 0x80)) break;
        }
    }
    return true;
}

Asn1Object_nid_no_patch* NewObject(std::span<const unsigned char> content) {
    if (!IsObjectEncoding(content)) {
        PutError(InvalidObjectEncoding);
        return nullptr;
    }
    if (content.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        PutError(TooLong);
        return nullptr;
    }
    auto* object = NewValue<Asn1Object_nid_no_patch>();
    if (!object) return nullptr;
    object->data = static_cast<unsigned char*>(malloc_nid_postfix(content.size()));
    if (!object->data) {
        free_nid_postfix(object);
        PutError(MallocFailure);
        return nullptr;
    }
    std::memcpy(const_cast<unsigned char*>(object->data), content.data(), content.size());
    object->length = static_cast<int>(content.size());
    object->flags = ObjectDynamic | ObjectDynamicData;
    object->nid = OBJ_obj2nid_nid_postfix(reinterpret_cast<const LibreSslAsn1Object*>(object));
    return object;
}

Asn1String* NewString(int type, std::span<const unsigned char> content) {
    if (content.size() > static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) {
        PutError(TooLong);
        return nullptr;
    }
    auto* value = NewValue<Asn1String>();
    if (!value) return nullptr;
    value->data = static_cast<unsigned char*>(calloc_nid_postfix(content.size() + 1, 1));
    if (!value->data) {
        free_nid_postfix(value);
        PutError(MallocFailure);
        return nullptr;
    }
    if (!content.empty()) std::memcpy(value->data, content.data(), content.size());
    value->length = static_cast<std::int32_t>(content.size());
    value->type = type;
    return value;
}

Asn1String* NewInteger(const Tlv& value) {
    const unsigned char* cursor = value.encoded.data();
    return static_cast<Asn1String*>(d2i_ASN1_INTEGER_nid_postfix(nullptr, &cursor,
        static_cast<std::int64_t>(value.encoded.size())));
}

Asn1Type* NewAny(const Tlv& value) {
    void* decoded = nullptr;
    int boolean = 0;
    if (value.tag == BooleanTag) {
        if (value.content.size() != 1) {
            PutError(LengthMismatch);
            return nullptr;
        }
        boolean = value.content.front();
    } else if (value.tag == NullTag) {
        if (!value.content.empty()) {
            PutError(LengthMismatch);
            return nullptr;
        }
    } else if (value.tag == ObjectTag) {
        decoded = NewObject(value.content);
    } else if (value.tag == IntegerTag) {
        decoded = NewInteger(value);
    } else if (value.tag == BitStringTag) {
        if (value.content.empty() || value.content.front() > 7) {
            PutError(InvalidBitStringBitsLeft);
            return nullptr;
        }
        decoded = NewString(BitStringTag, value.content.subspan(1));
        if (decoded) static_cast<Asn1String*>(decoded)->flags = BitsLeftFlag | value.content.front();
    } else {
        decoded = NewString(value.tag, value.content);
    }
    if (value.tag != BooleanTag && value.tag != NullTag && !decoded) return nullptr;
    auto* result = NewValue<Asn1Type>();
    if (!result) {
        if (value.tag == ObjectTag) ASN1_OBJECT_free_nid_postfix(static_cast<Asn1Object_nid_no_patch*>(decoded));
        else ASN1_OCTET_STRING_free_nid_postfix(static_cast<Asn1String*>(decoded));
        return nullptr;
    }
    result->type = value.tag;
    if (value.tag == BooleanTag) result->value.boolean = boolean;
    else result->value.pointer = decoded;
    return result;
}

bool Push(LibreSslStack* stack, void* value) {
    if (sk_push_nid_postfix(stack, value)) return true;
    PutError(MallocFailure);
    return false;
}

bool ParseAlgorithm(std::span<const unsigned char>& input, Algorithm*& result) {
    Tlv sequence;
    if (!Next(input, SequenceTag, sequence)) return false;
    result = NewValue<Algorithm>();
    if (!result) return false;
    std::span<const unsigned char> body = sequence.content;
    Tlv object;
    if (!Next(body, ObjectTag, object)) return false;
    result->algorithm = NewObject(object.content);
    if (!result->algorithm) return false;
    if (!body.empty()) {
        Tlv parameter;
        if (!ReadTlv(body, parameter)) return false;
        result->parameter = NewAny(parameter);
        if (!result->parameter) return false;
    }
    if (body.empty()) return true;
    PutError(SequenceLengthMismatch);
    return false;
}

LibreSslX509Name* ParseName(std::span<const unsigned char> content) {
    auto* name = NewValue<LibreSslX509Name>();
    if (!name) return nullptr;
    name->entries = sk_new_nid_postfix(nullptr);
    if (!name->entries) {
        free_nid_postfix(name);
        PutError(MallocFailure);
        return nullptr;
    }
    int setNumber = 0;
    while (!content.empty()) {
        Tlv set;
        if (!Next(content, SetTag, set) || set.content.empty()) {
            if (set.content.empty()) PutError(FieldMissing);
            LibreSslX509NameFree_nid_no_patch(name);
            return nullptr;
        }
        std::span<const unsigned char> entries = set.content;
        while (!entries.empty()) {
            Tlv sequence;
            if (!Next(entries, SequenceTag, sequence)) {
                LibreSslX509NameFree_nid_no_patch(name);
                return nullptr;
            }
            auto* entry = NewValue<LibreSslX509NameEntry>();
            if (!entry || !Push(name->entries, entry)) {
                free_nid_postfix(entry);
                LibreSslX509NameFree_nid_no_patch(name);
                return nullptr;
            }
            std::span<const unsigned char> body = sequence.content;
            Tlv object;
            Tlv value;
            if (!Next(body, ObjectTag, object) || !(entry->object = NewObject(object.content)) ||
                !ReadTlv(body, value)) {
                LibreSslX509NameFree_nid_no_patch(name);
                return nullptr;
            }
            bool stringTag = false;
            for (int candidate : NameStringTags) stringTag = stringTag || value.tag == candidate;
            if (!stringTag || !(entry->value = NewString(value.tag, value.content))) {
                if (!stringTag) PutError(WrongTag);
                LibreSslX509NameFree_nid_no_patch(name);
                return nullptr;
            }
            entry->set = setNumber;
            if (!body.empty()) {
                PutError(SequenceLengthMismatch);
                LibreSslX509NameFree_nid_no_patch(name);
                return nullptr;
            }
        }
        if (setNumber == std::numeric_limits<int>::max()) {
            PutError(TooLong);
            LibreSslX509NameFree_nid_no_patch(name);
            return nullptr;
        }
        ++setNumber;
    }
    return name;
}

bool ParseIssuerAndSerial(std::span<const unsigned char>& input, IssuerAndSerial*& result) {
    Tlv sequence;
    if (!Next(input, SequenceTag, sequence)) return false;
    result = NewValue<IssuerAndSerial>();
    if (!result) return false;
    std::span<const unsigned char> body = sequence.content;
    Tlv name;
    if (!Next(body, SequenceTag, name)) return false;
    result->issuer = ParseName(name.content);
    if (!result->issuer) return false;
    Tlv serial;
    if (!Next(body, IntegerTag, serial)) return false;
    result->serial = NewInteger(serial);
    if (!result->serial) return false;
    if (body.empty()) return true;
    PutError(SequenceLengthMismatch);
    return false;
}

bool ParseAttribute(std::span<const unsigned char>& input, LibreSslStack* stack) {
    Tlv sequence;
    if (!Next(input, SequenceTag, sequence)) return false;
    auto* attribute = NewValue<Attribute>();
    if (!attribute) return false;
    if (!Push(stack, attribute)) {
        free_nid_postfix(attribute);
        return false;
    }
    std::span<const unsigned char> body = sequence.content;
    Tlv object;
    if (!Next(body, ObjectTag, object)) return false;
    attribute->object = NewObject(object.content);
    if (!attribute->object) return false;
    Tlv values;
    if (!ReadTlv(body, values)) return false;
    if (values.tag == SetTag) {
        attribute->value = sk_new_nid_postfix(nullptr);
        if (!attribute->value) {
            PutError(MallocFailure);
            return false;
        }
        std::span<const unsigned char> elements = values.content;
        while (!elements.empty()) {
            Tlv element;
            if (!ReadTlv(elements, element)) return false;
            Asn1Type* any = NewAny(element);
            if (!any) return false;
            if (!Push(static_cast<LibreSslStack*>(attribute->value), any)) {
                ASN1_TYPE_free_nid_postfix(any);
                return false;
            }
        }
    } else {
        attribute->single = 1;
        attribute->value = NewAny(values);
        if (!attribute->value) return false;
    }
    if (body.empty()) return true;
    PutError(SequenceLengthMismatch);
    return false;
}

bool ParseAttributes(std::span<const unsigned char> content, LibreSslStack*& result) {
    result = sk_new_nid_postfix(nullptr);
    if (!result) {
        PutError(MallocFailure);
        return false;
    }
    while (!content.empty()) if (!ParseAttribute(content, result)) return false;
    return true;
}

bool ParseSigner(std::span<const unsigned char>& input, LibreSslStack* stack) {
    Tlv sequence;
    if (!Next(input, SequenceTag, sequence)) return false;
    auto* signer = NewValue<SignerInfo>();
    if (!signer) return false;
    if (!Push(stack, signer)) {
        free_nid_postfix(signer);
        return false;
    }
    std::span<const unsigned char> body = sequence.content;
    Tlv version;
    if (!Next(body, IntegerTag, version) || !(signer->version = NewInteger(version)) ||
        !ParseIssuerAndSerial(body, signer->issuerAndSerial) || !ParseAlgorithm(body, signer->digestAlgorithm)) return false;
    if (!body.empty() && body.front() == ExplicitContentTag) {
        Tlv attributes;
        if (!Next(body, ExplicitContentTag, attributes) ||
            !ParseAttributes(attributes.content, signer->authenticatedAttributes)) return false;
    }
    if (!ParseAlgorithm(body, signer->digestEncryptionAlgorithm)) return false;
    Tlv digest;
    if (!Next(body, OctetStringTag, digest)) return false;
    signer->encryptedDigest = NewString(OctetStringTag, digest.content);
    if (!signer->encryptedDigest) return false;
    if (!body.empty() && body.front() == RevocationsTag) {
        Tlv attributes;
        if (!Next(body, RevocationsTag, attributes) ||
            !ParseAttributes(attributes.content, signer->unauthenticatedAttributes)) return false;
    }
    if (body.empty()) return true;
    PutError(SequenceLengthMismatch);
    return false;
}

bool ParseRecipient(std::span<const unsigned char>& input, LibreSslStack* stack) {
    Tlv sequence;
    if (!Next(input, SequenceTag, sequence)) return false;
    auto* recipient = NewValue<RecipientInfo>();
    if (!recipient) return false;
    if (!Push(stack, recipient)) {
        free_nid_postfix(recipient);
        return false;
    }
    std::span<const unsigned char> body = sequence.content;
    Tlv version;
    if (!Next(body, IntegerTag, version) || !(recipient->version = NewInteger(version)) ||
        !ParseIssuerAndSerial(body, recipient->issuerAndSerial) ||
        !ParseAlgorithm(body, recipient->keyEncryptionAlgorithm)) return false;
    Tlv key;
    if (!Next(body, OctetStringTag, key)) return false;
    recipient->encryptedKey = NewString(OctetStringTag, key.content);
    if (!recipient->encryptedKey) return false;
    if (body.empty()) return true;
    PutError(SequenceLengthMismatch);
    return false;
}

template<typename TParser>
bool ParseSet(std::span<const unsigned char>& input, LibreSslStack*& result, TParser parser) {
    Tlv set;
    if (!Next(input, SetTag, set)) return false;
    result = sk_new_nid_postfix(nullptr);
    if (!result) {
        PutError(MallocFailure);
        return false;
    }
    std::span<const unsigned char> body = set.content;
    while (!body.empty()) if (!parser(body, result)) return false;
    return true;
}

bool ParseAlgorithms(std::span<const unsigned char>& input, LibreSslStack*& result) {
    return ParseSet(input, result, [](std::span<const unsigned char>& body, LibreSslStack* stack) {
        auto* algorithm = NewValue<Algorithm>();
        if (!algorithm) return false;
        if (!Push(stack, algorithm)) {
            free_nid_postfix(algorithm);
            return false;
        }
        Tlv sequence;
        if (!Next(body, SequenceTag, sequence)) return false;
        std::span<const unsigned char> encoded = sequence.encoded;
        Algorithm* parsed = nullptr;
        if (!ParseAlgorithm(encoded, parsed)) {
            if (parsed) {
                *algorithm = *parsed;
                free_nid_postfix(parsed);
            }
            return false;
        }
        *algorithm = *parsed;
        free_nid_postfix(parsed);
        return encoded.empty();
    });
}

bool ParseEncryptedContent(std::span<const unsigned char>& input, EncryptedContent*& result) {
    Tlv sequence;
    if (!Next(input, SequenceTag, sequence)) return false;
    result = NewValue<EncryptedContent>();
    if (!result) return false;
    std::span<const unsigned char> body = sequence.content;
    Tlv type;
    if (!Next(body, ObjectTag, type)) return false;
    result->contentType = NewObject(type.content);
    if (!result->contentType || !ParseAlgorithm(body, result->algorithm)) return false;
    if (!body.empty() && body.front() == ImplicitOctetStringTag) {
        Tlv data;
        if (!Next(body, ImplicitOctetStringTag, data)) return false;
        result->encryptedData = NewString(OctetStringTag, data.content);
        if (!result->encryptedData) return false;
    }
    if (body.empty()) return true;
    PutError(SequenceLengthMismatch);
    return false;
}

bool ParseCertificates(std::span<const unsigned char> content, LibreSslStack*& result) {
    result = sk_new_nid_postfix(nullptr);
    if (!result) {
        PutError(MallocFailure);
        return false;
    }
    while (!content.empty()) {
        Tlv certificate;
        if (!ReadTlv(content, certificate)) return false;
        const unsigned char* cursor = certificate.encoded.data();
        LibreSslX509* value = d2i_X509_nid_postfix(nullptr, &cursor,
            static_cast<std::int64_t>(certificate.encoded.size()));
        if (!value || cursor != certificate.encoded.data() + certificate.encoded.size()) return false;
        if (!Push(result, value)) {
            X509_free_nid_postfix(value);
            return false;
        }
    }
    return true;
}

bool ParseRevocations(std::span<const unsigned char> content, LibreSslStack*& result) {
    result = sk_new_nid_postfix(nullptr);
    if (!result) {
        PutError(MallocFailure);
        return false;
    }
    while (!content.empty()) {
        Tlv revocation;
        if (!ReadTlv(content, revocation)) return false;
        const unsigned char* cursor = revocation.encoded.data();
        LibreSsl3X509Crl* value = d2i_X509_CRL_nid_postfix(nullptr, &cursor,
            static_cast<std::int64_t>(revocation.encoded.size()));
        if (!value || cursor != revocation.encoded.data() + revocation.encoded.size()) return false;
        if (!Push(result, value)) {
            X509_CRL_free_nid_postfix(value);
            return false;
        }
    }
    return true;
}

Pkcs7* ParsePkcs7(std::span<const unsigned char>& input);

bool ParseNested(std::span<const unsigned char>& input, Pkcs7*& result) {
    const std::size_t before = input.size();
    result = ParsePkcs7(input);
    return result && input.size() < before;
}

bool ParseSigned(std::span<const unsigned char>& content, SignedData* value) {
    Tlv version;
    if (!Next(content, IntegerTag, version) || !(value->version = NewInteger(version)) ||
        !ParseAlgorithms(content, value->digestAlgorithms) || !ParseNested(content, value->contents)) return false;
    if (!content.empty() && content.front() == CertificatesTag) {
        Tlv certificates;
        if (!Next(content, CertificatesTag, certificates) ||
            !ParseCertificates(certificates.content, value->certificates)) return false;
    }
    if (!content.empty() && content.front() == RevocationsTag) {
        Tlv revocations;
        if (!Next(content, RevocationsTag, revocations) ||
            !ParseRevocations(revocations.content, value->revocations)) return false;
    }
    if (!ParseSet(content, value->signerInformation, ParseSigner)) return false;
    if (content.empty()) return true;
    PutError(SequenceLengthMismatch);
    return false;
}

bool ParseEnveloped(std::span<const unsigned char>& content, EnvelopedData* value) {
    Tlv version;
    if (!Next(content, IntegerTag, version) || !(value->version = NewInteger(version)) ||
        !ParseSet(content, value->recipientInformation, ParseRecipient) ||
        !ParseEncryptedContent(content, value->encryptedContent)) return false;
    if (content.empty()) return true;
    PutError(SequenceLengthMismatch);
    return false;
}

bool ParseSignedAndEnveloped(std::span<const unsigned char>& content, SignedAndEnvelopedData* value) {
    Tlv version;
    if (!Next(content, IntegerTag, version) || !(value->version = NewInteger(version)) ||
        !ParseSet(content, value->recipientInformation, ParseRecipient) ||
        !ParseAlgorithms(content, value->digestAlgorithms) ||
        !ParseEncryptedContent(content, value->encryptedContent)) return false;
    if (!content.empty() && content.front() == CertificatesTag) {
        Tlv certificates;
        if (!Next(content, CertificatesTag, certificates) ||
            !ParseCertificates(certificates.content, value->certificates)) return false;
    }
    if (!content.empty() && content.front() == RevocationsTag) {
        Tlv revocations;
        if (!Next(content, RevocationsTag, revocations) ||
            !ParseRevocations(revocations.content, value->revocations)) return false;
    }
    if (!ParseSet(content, value->signerInformation, ParseSigner)) return false;
    if (content.empty()) return true;
    PutError(SequenceLengthMismatch);
    return false;
}

bool ParseContent(Pkcs7* result, int nid, std::span<const unsigned char> content) {
    if (nid == Pkcs7Data) {
        Tlv value;
        if (!Next(content, OctetStringTag, value)) return false;
        result->content = NewString(OctetStringTag, value.content);
    } else if (nid < Pkcs7Signed || nid > Pkcs7Encrypted) {
        Tlv value;
        if (!ReadTlv(content, value)) return false;
        result->content = NewAny(value);
        if (!result->content) return false;
    } else {
        Tlv sequence;
        if (!Next(content, SequenceTag, sequence)) return false;
        std::span<const unsigned char> body = sequence.content;
        if (nid == Pkcs7Signed) {
            result->content = NewValue<SignedData>();
            if (!result->content || !ParseSigned(body, static_cast<SignedData*>(result->content))) return false;
        } else if (nid == Pkcs7Enveloped) {
            result->content = NewValue<EnvelopedData>();
            if (!result->content || !ParseEnveloped(body, static_cast<EnvelopedData*>(result->content))) return false;
        } else if (nid == Pkcs7SignedAndEnveloped) {
            result->content = NewValue<SignedAndEnvelopedData>();
            if (!result->content || !ParseSignedAndEnveloped(body,
                static_cast<SignedAndEnvelopedData*>(result->content))) return false;
        } else if (nid == Pkcs7Digest) {
            auto* value = NewValue<DigestData>();
            result->content = value;
            Tlv version;
            Tlv digest;
            if (!value || !Next(body, IntegerTag, version) || !(value->version = NewInteger(version)) ||
                !ParseAlgorithm(body, value->digestAlgorithm) || !ParseNested(body, value->contents) ||
                !Next(body, OctetStringTag, digest) ||
                !(value->digest = NewString(OctetStringTag, digest.content))) return false;
        } else if (nid == Pkcs7Encrypted) {
            auto* value = NewValue<EncryptedData>();
            result->content = value;
            Tlv version;
            if (!value || !Next(body, IntegerTag, version) || !(value->version = NewInteger(version)) ||
                !ParseEncryptedContent(body, value->encryptedContent)) return false;
        }
        if (!body.empty()) {
            PutError(SequenceLengthMismatch);
            return false;
        }
    }
    if (content.empty()) return true;
    PutError(SequenceLengthMismatch);
    return false;
}

Pkcs7* ParsePkcs7(std::span<const unsigned char>& input) {
    Tlv sequence;
    if (!Next(input, SequenceTag, sequence)) return nullptr;
    auto* result = NewValue<Pkcs7>();
    if (!result) return nullptr;
    std::span<const unsigned char> body = sequence.content;
    Tlv object;
    if (!Next(body, ObjectTag, object) || !(result->type = reinterpret_cast<LibreSslAsn1Object*>(NewObject(object.content)))) {
        PKCS7_free_nid_postfix(result);
        return nullptr;
    }
    const int nid = OBJ_obj2nid_nid_postfix(result->type);
    if (!body.empty()) {
        Tlv content;
        if (!Next(body, ExplicitContentTag, content) || !ParseContent(result, nid, content.content)) {
            PKCS7_free_nid_postfix(result);
            return nullptr;
        }
    }
    if (!body.empty()) {
        PutError(SequenceLengthMismatch);
        PKCS7_free_nid_postfix(result);
        return nullptr;
    }
    return result;
}

template<typename T>
bool GuestRead(const T* source, T& result) {
    const int savedErrno = errno;
    const bool copied = GuestCopyIn_nid_no_patch(&result, source, sizeof(result));
    errno = savedErrno;
    return copied;
}

template<typename T>
bool GuestWrite(T* destination, const T& value) {
    const int savedErrno = errno;
    const bool copied = GuestCopyOut_nid_no_patch(destination, &value, sizeof(value));
    errno = savedErrno;
    return copied;
}

Pkcs7* ReusePkcs7(Pkcs7* destination, Pkcs7* decoded) {
    Pkcs7 previous{};
    if (!GuestRead(destination, previous)) throw std::invalid_argument("d2i_PKCS7: unreadable output object");
    Pkcs7* release = NewValue<Pkcs7>();
    if (!release) {
        PKCS7_free_nid_postfix(decoded);
        return nullptr;
    }
    *release = previous;
    PKCS7_free_nid_postfix(release);
    const Pkcs7 replacement = *decoded;
    if (!GuestWrite(destination, replacement)) {
        PKCS7_free_nid_postfix(decoded);
        throw std::invalid_argument("d2i_PKCS7: unwritable output object");
    }
    *decoded = {};
    free_nid_postfix(decoded);
    return destination;
}

}

extern "C" {

void* APS5_VABI d2i_PKCS7_nid_postfix(void** output, const unsigned char** input, std::int64_t length) {
    if (!input || length < 0) {
        PutError(BadObjectHeader);
        return nullptr;
    }
    const unsigned char* source = nullptr;
    if (!GuestRead(input, source) || !source || !GuestWrite(input, source)) {
        PutError(BadObjectHeader);
        return nullptr;
    }
    void* old = nullptr;
    if (output && (!GuestRead(output, old) || !GuestWrite(output, old))) {
        PutError(BadObjectHeader);
        return nullptr;
    }
    std::vector<unsigned char> encoded(static_cast<std::size_t>(length));
    if (!encoded.empty()) {
        const int savedErrno = errno;
        const bool copied = GuestCopyIn_nid_no_patch(encoded.data(), source, encoded.size());
        errno = savedErrno;
        if (!copied) {
            PutError(BadObjectHeader);
            return nullptr;
        }
    }
    std::span<const unsigned char> remaining(encoded);
    Pkcs7* result = ParsePkcs7(remaining);
    if (!result) {
        if (output && old) {
            PKCS7_free_nid_postfix(old);
            old = nullptr;
            GuestWrite(output, old);
        }
        return nullptr;
    }
    const unsigned char* advanced = source + (encoded.size() - remaining.size());
    if (!GuestWrite(input, advanced)) {
        PKCS7_free_nid_postfix(result);
        return nullptr;
    }
    if (!output) return result;
    if (old) result = ReusePkcs7(static_cast<Pkcs7*>(old), result);
    if (!result || !GuestWrite(output, static_cast<void*>(result))) {
        PKCS7_free_nid_postfix(result);
        return nullptr;
    }
    return result;
}

}
