#include "prx/libSceLibreSsl3/libSceLibreSsl3.hpp"
#include "prx/libSceLibreSsl/include/Api.hpp"
#include "prx/libc/include/ApplicationHeap.hpp"
#include "prx/libc/include/general/VabiMacros.hpp"

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <source_location>
#include <stdexcept>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>

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

std::unordered_map<void*, std::size_t> allocations;
std::unordered_set<void*> zeroed;

void* APS5_VABI Allocate_nid_no_patch(std::size_t size) {
    void* result = std::malloc(size);
    if (result) allocations.emplace(result, size);
    return result;
}

void APS5_VABI Free_nid_no_patch(void* pointer) {
    if (!pointer) return;
    const auto found = allocations.find(pointer);
    if (found == allocations.end()) std::abort();
    if (zeroed.erase(pointer) != 0) {
        const auto* bytes = static_cast<const unsigned char*>(pointer);
        for (std::size_t index = 0; index < found->second; ++index) {
            if (bytes[index] != 0) std::abort();
        }
    }
    allocations.erase(found);
    std::free(pointer);
}

void* APS5_VABI Callocate_nid_no_patch(std::size_t count, std::size_t size) {
    void* result = std::calloc(count, size);
    if (result) allocations.emplace(result, count * size);
    return result;
}

void* APS5_VABI Reallocate_nid_no_patch(void* pointer, std::size_t size) {
    if (!pointer) return Allocate_nid_no_patch(size);
    const auto found = allocations.find(pointer);
    if (found == allocations.end()) std::abort();
    void* result = std::realloc(pointer, size);
    if (!result) return nullptr;
    allocations.erase(found);
    allocations.emplace(result, size);
    return result;
}

void* APS5_VABI UnexpectedAlign_nid_no_patch(std::size_t, std::size_t) { throw std::runtime_error("unexpected aligned allocation"); }
void* APS5_VABI UnexpectedRealign_nid_no_patch(void*, std::size_t, std::size_t) { throw std::runtime_error("unexpected aligned reallocation"); }
int APS5_VABI UnexpectedPosixAlign_nid_no_patch(void**, std::size_t, std::size_t) { throw std::runtime_error("unexpected posix_memalign"); }

void Require(bool condition, std::source_location location = std::source_location::current()) {
    if (condition) return;
    std::fprintf(stderr, "LibreSSL3 X509 item free check failed at line %u\n", location.line());
    std::abort();
}

template<typename TAction>
void RequireNoException(TAction action, std::source_location location = std::source_location::current()) {
    try {
        action();
    } catch (...) {
        Require(false, location);
    }
}

template<typename TAction>
void RequireNotImplemented(TAction action, std::source_location location = std::source_location::current()) {
    try {
        action();
    } catch (const std::runtime_error&) {
        return;
    }
    Require(false, location);
}

template<typename TAction>
void RequireInvalidArgument(TAction action, std::source_location location = std::source_location::current()) {
    try {
        action();
    } catch (const std::invalid_argument&) {
        return;
    }
    Require(false, location);
}

Asn1String* MakeString(int type, std::initializer_list<unsigned char> bytes) {
    auto* string = static_cast<Asn1String*>(Callocate_nid_no_patch(1, sizeof(Asn1String)));
    Require(string != nullptr);
    string->length = static_cast<int>(bytes.size());
    string->type = type;
    if (!bytes.size()) return string;
    string->data = static_cast<unsigned char*>(Allocate_nid_no_patch(bytes.size()));
    Require(string->data != nullptr);
    std::memcpy(string->data, bytes.begin(), bytes.size());
    zeroed.insert(string->data);
    return string;
}

template<typename T>
T* Make() {
    auto* value = static_cast<T*>(Callocate_nid_no_patch(1, sizeof(T)));
    Require(value != nullptr);
    return value;
}

Asn1Object_nid_no_patch* MakeObject(int nid) {
    auto* object = Make<Asn1Object_nid_no_patch>();
    object->nid = nid;
    object->flags = 1;
    return object;
}

LibreSslStack* MakeStack(std::initializer_list<void*> values) {
    auto* stack = Make<LibreSslStack>();
    stack->num = static_cast<int>(values.size());
    stack->numAlloc = stack->num;
    if (!values.size()) return stack;
    stack->data = static_cast<char**>(Callocate_nid_no_patch(values.size(), sizeof(char*)));
    Require(stack->data != nullptr);
    int index = 0;
    for (void* value : values) stack->data[index++] = static_cast<char*>(value);
    return stack;
}

Asn1Type* MakeNullType() {
    auto* value = Make<Asn1Type>();
    value->type = 5;
    return value;
}

Algorithm* MakeAlgorithm() {
    auto* algorithm = Make<Algorithm>();
    algorithm->algorithm = MakeObject(6);
    algorithm->parameter = MakeNullType();
    return algorithm;
}

Attribute* MakeAttribute(bool single) {
    auto* attribute = Make<Attribute>();
    attribute->object = MakeObject(9);
    attribute->single = single ? 1 : 0;
    attribute->value = single ? static_cast<void*>(MakeNullType()) : MakeStack({MakeNullType()});
    return attribute;
}

IssuerAndSerial* MakeIssuerAndSerial() {
    auto* value = Make<IssuerAndSerial>();
    value->serial = MakeString(2, {1});
    return value;
}

SignerInfo* MakeSignerInfo() {
    auto* value = Make<SignerInfo>();
    value->version = MakeString(2, {1});
    value->issuerAndSerial = MakeIssuerAndSerial();
    value->digestAlgorithm = MakeAlgorithm();
    value->authenticatedAttributes = MakeStack({MakeAttribute(true)});
    value->digestEncryptionAlgorithm = MakeAlgorithm();
    value->encryptedDigest = MakeString(4, {2, 3});
    value->unauthenticatedAttributes = MakeStack({MakeAttribute(false)});
    value->key = EVP_PKEY_new_nid_postfix();
    Require(value->key != nullptr);
    return value;
}

RecipientInfo* MakeRecipientInfo() {
    auto* value = Make<RecipientInfo>();
    value->version = MakeString(2, {0});
    value->issuerAndSerial = MakeIssuerAndSerial();
    value->keyEncryptionAlgorithm = MakeAlgorithm();
    value->encryptedKey = MakeString(4, {4, 5});
    return value;
}

EncryptedContent* MakeEncryptedContent() {
    auto* value = Make<EncryptedContent>();
    value->contentType = MakeObject(21);
    value->algorithm = MakeAlgorithm();
    value->encryptedData = MakeString(4, {6, 7});
    value->cipher = reinterpret_cast<void*>(std::uintptr_t{1});
    return value;
}

Pkcs7* MakePkcs7(int nid, void* content) {
    auto* value = Make<Pkcs7>();
    value->type = reinterpret_cast<LibreSslAsn1Object*>(MakeObject(nid));
    value->content = content;
    return value;
}

LibreSslStack* MakeIssuer() {
    auto* stack = static_cast<LibreSslStack*>(Callocate_nid_no_patch(1, sizeof(LibreSslStack)));
    auto* entries = static_cast<char**>(Callocate_nid_no_patch(1, sizeof(char*)));
    auto* name = static_cast<LibreSslGeneralName*>(Callocate_nid_no_patch(1, sizeof(LibreSslGeneralName)));
    Require(stack != nullptr && entries != nullptr && name != nullptr);
    name->type = 2;
    name->value = MakeString(22, {'c', 'a'});
    entries[0] = reinterpret_cast<char*>(name);
    stack->num = 1;
    stack->data = entries;
    stack->numAlloc = 1;
    return stack;
}

void TestNull() {
    RequireNoException([] { AUTHORITY_KEYID_free_nid_postfix(nullptr); });
    RequireNoException([] { X509_CRL_free_nid_postfix(nullptr); });
    RequireNoException([] { PKCS7_free_nid_postfix(nullptr); });
    void* const unreadable = reinterpret_cast<void*>(std::uintptr_t{1});
    Require(X509_check_akid_nid_postfix(nullptr, nullptr) == 0);
    Require(X509_check_akid_nid_postfix(unreadable, nullptr) == 0);
}

void TestNonNull() {
    void* const unreadable = reinterpret_cast<void*>(std::uintptr_t{1});
    errno = EDOM;
    RequireInvalidArgument([&] { AUTHORITY_KEYID_free_nid_postfix(unreadable); });
    Require(errno == EDOM);
    RequireInvalidArgument([&] { PKCS7_free_nid_postfix(unreadable); });
    Require(errno == EDOM);
    RequireNotImplemented([&] { X509_check_akid_nid_postfix(nullptr, unreadable); });
    RequireNotImplemented([&] { X509_check_akid_nid_postfix(unreadable, unreadable); });
}

void TestPkcs7Types() {
    PKCS7_free_nid_postfix(MakePkcs7(21, MakeString(4, {1, 2})));
    Require(allocations.empty());
    PKCS7_free_nid_postfix(MakePkcs7(22, Make<SignedData>()));
    Require(allocations.empty());
    PKCS7_free_nid_postfix(MakePkcs7(23, Make<EnvelopedData>()));
    Require(allocations.empty());
    PKCS7_free_nid_postfix(MakePkcs7(24, Make<SignedAndEnvelopedData>()));
    Require(allocations.empty());
    PKCS7_free_nid_postfix(MakePkcs7(25, Make<DigestData>()));
    Require(allocations.empty());
    PKCS7_free_nid_postfix(MakePkcs7(26, Make<EncryptedData>()));
    Require(allocations.empty());
    PKCS7_free_nid_postfix(MakePkcs7(0, MakeNullType()));
    Require(allocations.empty());
}

void TestPkcs7Nested() {
    auto* signedData = Make<SignedData>();
    signedData->version = MakeString(2, {1});
    signedData->digestAlgorithms = MakeStack({MakeAlgorithm()});
    signedData->certificates = MakeStack({nullptr});
    signedData->revocations = MakeStack({nullptr});
    signedData->signerInformation = MakeStack({MakeSignerInfo()});
    signedData->contents = MakePkcs7(21, MakeString(4, {8, 9}));
    PKCS7_free_nid_postfix(MakePkcs7(22, signedData));
    Require(allocations.empty());

    auto* enveloped = Make<EnvelopedData>();
    enveloped->version = MakeString(2, {0});
    enveloped->recipientInformation = MakeStack({MakeRecipientInfo()});
    enveloped->encryptedContent = MakeEncryptedContent();
    PKCS7_free_nid_postfix(MakePkcs7(23, enveloped));
    Require(allocations.empty());

    auto* combined = Make<SignedAndEnvelopedData>();
    combined->version = MakeString(2, {1});
    combined->digestAlgorithms = MakeStack({MakeAlgorithm()});
    combined->certificates = MakeStack({nullptr});
    combined->revocations = MakeStack({nullptr});
    combined->signerInformation = MakeStack({MakeSignerInfo()});
    combined->encryptedContent = MakeEncryptedContent();
    combined->recipientInformation = MakeStack({MakeRecipientInfo()});
    PKCS7_free_nid_postfix(MakePkcs7(24, combined));
    Require(allocations.empty());

    auto* digest = Make<DigestData>();
    digest->version = MakeString(2, {0});
    digest->digestAlgorithm = MakeAlgorithm();
    digest->contents = MakePkcs7(21, MakeString(4, {}));
    digest->digest = MakeString(4, {10});
    PKCS7_free_nid_postfix(MakePkcs7(25, digest));
    Require(allocations.empty());

    auto* encrypted = Make<EncryptedData>();
    encrypted->version = MakeString(2, {0});
    encrypted->encryptedContent = MakeEncryptedContent();
    PKCS7_free_nid_postfix(MakePkcs7(26, encrypted));
    Require(allocations.empty());
}

void TestPkcs7DynamicType() {
    constexpr unsigned char DataOid[]{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01};
    auto* object = MakeObject(0);
    auto* data = static_cast<unsigned char*>(Allocate_nid_no_patch(sizeof(DataOid)));
    Require(data != nullptr);
    std::memcpy(data, DataOid, sizeof(DataOid));
    object->data = data;
    object->length = sizeof(DataOid);
    object->flags = 9;
    zeroed.insert(data);
    auto* value = Make<Pkcs7>();
    value->type = reinterpret_cast<LibreSslAsn1Object*>(object);
    value->content = MakeString(4, {11});
    PKCS7_free_nid_postfix(value);
    Require(allocations.empty());
}

void TestAuthorityKeyId() {
    auto* id = static_cast<AuthorityKeyId*>(Callocate_nid_no_patch(1, sizeof(AuthorityKeyId)));
    Require(id != nullptr);
    id->keyId = MakeString(4, {1, 2, 3});
    id->issuer = MakeIssuer();
    id->serial = MakeString(2, {4, 5});
    AUTHORITY_KEYID_free_nid_postfix(id);
    Require(allocations.empty());

    id = static_cast<AuthorityKeyId*>(Callocate_nid_no_patch(1, sizeof(AuthorityKeyId)));
    Require(id != nullptr);
    AUTHORITY_KEYID_free_nid_postfix(id);
    Require(allocations.empty());
}

}

int main() {
    static_assert(std::is_same_v<decltype(&PKCS7_free_nid_postfix), void (APS5_VABI*)(void*)>);
    std::array<void*, 10> api{
        reinterpret_cast<void*>(Allocate_nid_no_patch), reinterpret_cast<void*>(Free_nid_no_patch),
        reinterpret_cast<void*>(Callocate_nid_no_patch), reinterpret_cast<void*>(Reallocate_nid_no_patch),
        reinterpret_cast<void*>(UnexpectedAlign_nid_no_patch), reinterpret_cast<void*>(UnexpectedRealign_nid_no_patch),
        reinterpret_cast<void*>(UnexpectedPosixAlign_nid_no_patch)};
    ApplicationHeapRegister_nid_no_patch(api.data());
    TestNull();
    TestNonNull();
    TestAuthorityKeyId();
    TestPkcs7Types();
    TestPkcs7Nested();
    TestPkcs7DynamicType();
    std::puts("LibreSSL3 X509 item free tests passed");
}
