#include "prx/libSceLibreSsl3/include/Api.hpp"
#include "prx/libSceLibreSsl/include/Api.hpp"
#include "prx/libc/include/Api.hpp"
#include "prx/libc/include/General.hpp"
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

struct AuthorityKeyId {
    Asn1String* keyId;
    LibreSslStack* issuer;
    Asn1String* serial;
};

struct X509WithExtensions {
    LibreSslX509 prefix;
    char* name;
    LibreSslStack* exData;
    std::int64_t exPathLength;
    std::int64_t exProxyPathLength;
    std::uint64_t exFlags;
    std::uint64_t exKeyUsage;
    std::uint64_t exExtendedKeyUsage;
    std::uint64_t exNsCert;
    Asn1String* subjectKeyId;
};

static_assert(sizeof(X509WithExtensions) == 104 && offsetof(X509WithExtensions, subjectKeyId) == 96);

static_assert(sizeof(AuthorityKeyId) == 24 && offsetof(AuthorityKeyId, serial) == 16);

AuthorityKeyId ReadAuthorityKeyId(const void* source) {
    AuthorityKeyId value{};
    const int savedErrno = errno;
    const bool copied = GuestCopyIn_nid_no_patch(&value, source, sizeof(value));
    errno = savedErrno;
    if (!copied) throw std::invalid_argument(std::string(__func__) + ": unreadable authority key identifier");
    return value;
}

template<typename T>
T ReadGuest(const T* source, const char* function) {
    T value{};
    const int savedErrno = errno;
    const bool copied = GuestCopyIn_nid_no_patch(&value, source, sizeof(value));
    errno = savedErrno;
    if (!copied) throw std::invalid_argument(std::string(function) + ": unreadable object");
    return value;
}

std::vector<unsigned char> ReadBytes(const unsigned char* source, int length, const char* function) {
    if (length < 0) throw std::invalid_argument(std::string(function) + ": negative length");
    std::vector<unsigned char> result(static_cast<std::size_t>(length));
    if (!length) return result;
    if (!source) throw std::invalid_argument(std::string(function) + ": null data");
    const int savedErrno = errno;
    const bool copied = GuestCopyIn_nid_no_patch(result.data(), source, result.size());
    errno = savedErrno;
    if (!copied) throw std::invalid_argument(std::string(function) + ": unreadable data");
    return result;
}

int CompareInteger(const Asn1String* first, const Asn1String* second, const char* function) {
    const Asn1String left = ReadGuest(first, function);
    const Asn1String right = ReadGuest(second, function);
    const bool leftNegative = (left.type & 0x100) != 0;
    const bool rightNegative = (right.type & 0x100) != 0;
    if (leftNegative != rightNegative) return leftNegative ? -1 : 1;
    const int order = ASN1_OCTET_STRING_cmp_nid_postfix(first, second);
    return leftNegative ? -order : order;
}

int CompareNames(const LibreSslX509Name* first, const LibreSslX509Name* second, const char* function) {
    const LibreSslX509Name left = ReadGuest(first, function);
    const LibreSslX509Name right = ReadGuest(second, function);
    if (left.modified || right.modified || !left.canonEnc || !right.canonEnc)
        NotImplemented_nid_no_patch(function);
    if (left.canonEnclen < 0 || right.canonEnclen < 0)
        throw std::invalid_argument(std::string(function) + ": negative canonical name length");
    if (left.canonEnclen != right.canonEnclen) return left.canonEnclen < right.canonEnclen ? -1 : 1;
    const auto a = ReadBytes(left.canonEnc, left.canonEnclen, function);
    const auto b = ReadBytes(right.canonEnc, right.canonEnclen, function);
    return a.empty() ? 0 : std::memcmp(a.data(), b.data(), a.size());
}

LibreSslGeneralName ReadGeneralName(const LibreSslStack& stack, int index, const char* function) {
    if (stack.num < 0 || stack.num > stack.numAlloc)
        throw std::invalid_argument(std::string(function) + ": invalid issuer stack");
    if (!stack.data) throw std::invalid_argument(std::string(function) + ": null issuer entries");
    auto* entry = ReadGuest(stack.data + index, function);
    if (!entry) throw std::invalid_argument(std::string(function) + ": null issuer name");
    return ReadGuest(reinterpret_cast<const LibreSslGeneralName*>(entry), function);
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

int APS5_VABI X509_check_akid_nid_postfix(void* issuer, void* authorityKeyId) {
    constexpr const char* function = "X509_check_akid_nid_postfix";
    if (!authorityKeyId) return 0;
    const AuthorityKeyId id = ReadAuthorityKeyId(authorityKeyId);
    X509WithExtensions certificate{};
    bool certificateRead = false;
    const auto readCertificate = [&] {
        if (!certificateRead) {
            certificate = ReadGuest(static_cast<const X509WithExtensions*>(issuer), function);
            certificateRead = true;
        }
    };
    if (id.keyId) {
        readCertificate();
        if (certificate.subjectKeyId && ASN1_OCTET_STRING_cmp_nid_postfix(id.keyId, certificate.subjectKeyId)) return 30;
    }
    if (id.serial) {
        readCertificate();
        const auto info = ReadGuest(static_cast<const LibreSslX509CertInfo*>(certificate.prefix.certificateInfo), function);
        if (CompareInteger(static_cast<const Asn1String*>(info.serialNumber), id.serial, function)) return 31;
    }
    if (id.issuer) {
        const LibreSslStack names = ReadGuest(id.issuer, function);
        if (names.num < 0 || names.num > names.numAlloc)
            throw std::invalid_argument(std::string(function) + ": invalid issuer stack");
        for (int index = 0; index < names.num; ++index) {
            const LibreSslGeneralName name = ReadGeneralName(names, index, function);
            if (name.type != 4) continue;
            readCertificate();
            const auto info = ReadGuest(static_cast<const LibreSslX509CertInfo*>(certificate.prefix.certificateInfo), function);
            if (name.value && CompareNames(static_cast<const LibreSslX509Name*>(name.value),
                                           static_cast<const LibreSslX509Name*>(info.issuer), function))
                return 31;
            break;
        }
    }
    return 0;
}

void APS5_VABI PKCS7_free_nid_postfix(void* pkcs7) {
    if (!pkcs7) return;
    NotImplemented_nid_no_patch(__func__);
}

}
