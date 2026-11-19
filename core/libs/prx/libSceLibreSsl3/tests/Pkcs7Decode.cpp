#include "prx/libSceLibreSsl3/include/Api.hpp"
#include "prx/libc/include/ApplicationHeap.hpp"
#include "prx/libc/include/general/VabiMacros.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <source_location>
#include <stdexcept>
#include <type_traits>
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
    void* encryptedContent;
};

struct SignedAndEnvelopedData {
    Asn1String* version;
    LibreSslStack* digestAlgorithms;
    LibreSslStack* certificates;
    LibreSslStack* revocations;
    LibreSslStack* signerInformation;
    void* encryptedContent;
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
    void* encryptedContent;
};

static_assert(std::is_same_v<decltype(&d2i_PKCS7_nid_postfix),
    void* (APS5_VABI *)(void**, const unsigned char**, std::int64_t)>);

void* APS5_VABI Allocate(std::size_t bytes) { return std::malloc(bytes ? bytes : 1); }
void APS5_VABI Release(void* block) { std::free(block); }
void* APS5_VABI AllocateZeroed(std::size_t count, std::size_t bytes) {
    return std::calloc(count ? count : 1, bytes ? bytes : 1);
}
void* APS5_VABI Reallocate(void* block, std::size_t bytes) { return std::realloc(block, bytes ? bytes : 1); }
void* APS5_VABI Align(std::size_t, std::size_t) { return nullptr; }
void* APS5_VABI Realign(void*, std::size_t, std::size_t) { return nullptr; }
int APS5_VABI PosixAlign(void**, std::size_t, std::size_t) { return 12; }

void InitializeHeap() {
    void* const api[10] {
        reinterpret_cast<void*>(&Allocate), reinterpret_cast<void*>(&Release), reinterpret_cast<void*>(&AllocateZeroed),
        reinterpret_cast<void*>(&Reallocate), reinterpret_cast<void*>(&Align), reinterpret_cast<void*>(&Realign),
        reinterpret_cast<void*>(&PosixAlign),
    };
    ApplicationHeapRegister_nid_no_patch(api);
}

[[noreturn]] void Fail(const char* message, std::source_location location = std::source_location::current()) {
    std::fprintf(stderr, "%s:%u: %s\n", location.file_name(), location.line(), message);
    std::exit(1);
}

void Require(bool condition, const char* message,
    std::source_location location = std::source_location::current()) {
    if (!condition) Fail(message, location);
}

std::vector<unsigned char> Tlv(unsigned char tag, const std::vector<unsigned char>& content) {
    Require(content.size() < 128, "test TLV remains short-form");
    std::vector<unsigned char> result{tag, static_cast<unsigned char>(content.size())};
    result.insert(result.end(), content.begin(), content.end());
    return result;
}

std::vector<unsigned char> Join(std::initializer_list<std::vector<unsigned char>> values) {
    std::vector<unsigned char> result;
    for (const auto& value : values) result.insert(result.end(), value.begin(), value.end());
    return result;
}

std::vector<unsigned char> Integer(unsigned char value) {
    return Tlv(0x02, {value});
}

std::vector<unsigned char> Object(std::initializer_list<unsigned char> value) {
    return Tlv(0x06, value);
}

std::vector<unsigned char> ContentType(unsigned char suffix) {
    return Object({0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, suffix});
}

std::vector<unsigned char> AlgorithmIdentifier() {
    return Tlv(0x30, Join({Object({0x2b, 0x0e, 0x03, 0x02, 0x1a}), Tlv(0x05, {})}));
}

std::vector<unsigned char> IssuerAndSerial() {
    return Tlv(0x30, Join({Tlv(0x30, {}), Integer(1)}));
}

std::vector<unsigned char> Signer() {
    return Tlv(0x30, Join({Integer(1), IssuerAndSerial(), AlgorithmIdentifier(),
        AlgorithmIdentifier(), Tlv(0x04, {0xaa})}));
}

std::vector<unsigned char> Recipient() {
    return Tlv(0x30, Join({Integer(0), IssuerAndSerial(), AlgorithmIdentifier(), Tlv(0x04, {0xbb})}));
}

std::vector<unsigned char> EncryptedContentInfo() {
    return Tlv(0x30, Join({ContentType(1), AlgorithmIdentifier(), Tlv(0x80, {0xcc})}));
}

std::vector<unsigned char> Pkcs7Value(unsigned char suffix, const std::vector<unsigned char>& content) {
    return Tlv(0x30, content.empty() ? ContentType(suffix) :
        Join({ContentType(suffix), Tlv(0xa0, content)}));
}

std::vector<unsigned char> DataValue(std::initializer_list<unsigned char> bytes = {}) {
    return Pkcs7Value(1, Tlv(0x04, bytes));
}

Pkcs7* Decode(const std::vector<unsigned char>& encoded) {
    const unsigned char* input = encoded.data();
    auto* result = static_cast<Pkcs7*>(d2i_PKCS7_nid_postfix(nullptr, &input,
        static_cast<std::int64_t>(encoded.size())));
    Require(result != nullptr, "decode succeeds");
    Require(input == encoded.data() + encoded.size(), "decode advances across one object");
    return result;
}

void TestDataAndReplacement() {
    const std::vector<unsigned char> first = DataValue({1, 2, 3});
    const std::vector<unsigned char> second = DataValue({4, 5});
    Pkcs7* value = Decode(first);
    Require(value->type && value->type->nid == 21, "data content OID is resolved");
    const auto* data = static_cast<const Asn1String*>(value->content);
    Require(data && data->length == 3 && data->data[2] == 3, "data octets are decoded");
    const unsigned char* input = second.data();
    void* output = value;
    void* replacement = d2i_PKCS7_nid_postfix(&output, &input, static_cast<std::int64_t>(second.size()));
    Require(replacement == value && output == value, "output owner is reused");
    Require(input == second.data() + second.size(), "replacement advances the cursor");
    PKCS7_free_nid_postfix(output);
}

void TestAllContentChoices() {
    const std::vector<unsigned char> nested = Pkcs7Value(1, {});
    const std::vector<unsigned char> algorithms = Tlv(0x31, AlgorithmIdentifier());
    const std::vector<unsigned char> signers = Tlv(0x31, Signer());
    const std::vector<unsigned char> recipients = Tlv(0x31, Recipient());

    Pkcs7* signedValue = Decode(Pkcs7Value(2, Tlv(0x30,
        Join({Integer(1), algorithms, nested, signers}))));
    auto* signedData = static_cast<SignedData*>(signedValue->content);
    Require(signedData && signedData->digestAlgorithms->num == 1 &&
        signedData->signerInformation->num == 1 && signedData->contents->type->nid == 21,
        "signed-data graph is populated");
    PKCS7_free_nid_postfix(signedValue);

    Pkcs7* envelopedValue = Decode(Pkcs7Value(3, Tlv(0x30,
        Join({Integer(0), recipients, EncryptedContentInfo()}))));
    auto* enveloped = static_cast<EnvelopedData*>(envelopedValue->content);
    Require(enveloped && enveloped->recipientInformation->num == 1 && enveloped->encryptedContent,
        "enveloped-data graph is populated");
    PKCS7_free_nid_postfix(envelopedValue);

    Pkcs7* combinedValue = Decode(Pkcs7Value(4, Tlv(0x30,
        Join({Integer(1), recipients, algorithms, EncryptedContentInfo(), signers}))));
    auto* combined = static_cast<SignedAndEnvelopedData*>(combinedValue->content);
    Require(combined && combined->recipientInformation->num == 1 &&
        combined->digestAlgorithms->num == 1 && combined->signerInformation->num == 1,
        "signed-and-enveloped graph is populated");
    PKCS7_free_nid_postfix(combinedValue);

    Pkcs7* digestValue = Decode(Pkcs7Value(5, Tlv(0x30,
        Join({Integer(0), AlgorithmIdentifier(), nested, Tlv(0x04, {0xdd})}))));
    auto* digest = static_cast<DigestData*>(digestValue->content);
    Require(digest && digest->digestAlgorithm && digest->contents->type->nid == 21 &&
        digest->digest->data[0] == 0xdd, "digested-data graph is populated");
    PKCS7_free_nid_postfix(digestValue);

    Pkcs7* encryptedValue = Decode(Pkcs7Value(6, Tlv(0x30,
        Join({Integer(0), EncryptedContentInfo()}))));
    auto* encrypted = static_cast<EncryptedData*>(encryptedValue->content);
    Require(encrypted && encrypted->encryptedContent, "encrypted-data graph is populated");
    PKCS7_free_nid_postfix(encryptedValue);

    Pkcs7* otherValue = Decode(Tlv(0x30, Join({Object({0x2a, 0x03}), Tlv(0xa0, Integer(7))})));
    auto* other = static_cast<Asn1Type*>(otherValue->content);
    Require(otherValue->type->nid == 0 && other && other->type == 2, "unknown content uses the ANY choice");
    PKCS7_free_nid_postfix(otherValue);
}

void TestFailuresDoNotMutateOwners() {
    const std::vector<unsigned char> valid = DataValue({9});
    Pkcs7* existing = Decode(valid);
    const std::array<unsigned char, 3> malformed{0x30, 0x02, 0x06};
    const unsigned char* input = malformed.data();
    void* output = existing;
    Require(!d2i_PKCS7_nid_postfix(&output, &input, malformed.size()), "malformed DER fails");
    Require(!output && input == malformed.data(), "failure frees the reused owner and preserves the cursor");
    input = valid.data();
    Require(!d2i_PKCS7_nid_postfix(nullptr, &input, -1), "negative length fails");
    Require(input == valid.data(), "negative length preserves cursor");
    Require(!d2i_PKCS7_nid_postfix(nullptr, nullptr, valid.size()), "null cursor owner fails");
    const unsigned char** invalid = reinterpret_cast<const unsigned char**>(static_cast<std::uintptr_t>(1));
    Require(!d2i_PKCS7_nid_postfix(nullptr, invalid, valid.size()), "unreadable cursor owner fails");
}

}

int main() {
    InitializeHeap();
    TestDataAndReplacement();
    TestAllContentChoices();
    TestFailuresDoNotMutateOwners();
}
