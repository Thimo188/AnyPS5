#include "prx/libSceIcu/include/LegacyExports.hpp"
#include "rbbidata.h"
#include "ucmndata.h"
#include "unicode/umutablecptrie.h"
#include "udataswp.h"
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

void Expect(bool condition, const char* what) {
    if (condition) return;
    std::fprintf(stderr, "failed: %s\n", what);
    std::abort();
}

std::vector<std::uint8_t> TrieData() {
    UErrorCode status = U_ZERO_ERROR;
    UMutableCPTrie* mutableTrie = umutablecptrie_open(0, 1, &status);
    Expect(mutableTrie != nullptr && status == U_ZERO_ERROR, "mutable trie opens");
    umutablecptrie_setRange(mutableTrie, 0x41, 0x5a, 2, &status);
    UCPTrie* trie = umutablecptrie_buildImmutable(mutableTrie, UCPTRIE_TYPE_SMALL, UCPTRIE_VALUE_BITS_8, &status);
    umutablecptrie_close(mutableTrie);
    Expect(trie != nullptr && status == U_ZERO_ERROR, "immutable trie builds");
    const auto size = ucptrie_toBinary(trie, nullptr, 0, &status);
    Expect(size > 0 && status == U_BUFFER_OVERFLOW_ERROR, "trie preflights");
    status = U_ZERO_ERROR;
    std::vector<std::uint32_t> storage((size + 3) / 4);
    Expect(ucptrie_toBinary(trie, storage.data(), size, &status) == size && status == U_ZERO_ERROR,
           "trie serializes");
    ucptrie_close(trie);
    const auto* first = reinterpret_cast<const std::uint8_t*>(storage.data());
    return {first, first + size};
}

std::vector<std::uint8_t> BreakData() {
    const auto trie = TrieData();
    const std::size_t headerSize = sizeof(DataHeader);
    const std::size_t breakSize = sizeof(icu::RBBIDataHeader) + trie.size();
    std::vector<std::uint8_t> bytes(headerSize + breakSize);
    auto* data = reinterpret_cast<DataHeader*>(bytes.data());
    data->dataHeader.headerSize = static_cast<std::uint16_t>(headerSize);
    data->dataHeader.magic1 = 0xda;
    data->dataHeader.magic2 = 0x27;
    data->info.size = sizeof(UDataInfo);
    data->info.isBigEndian = U_IS_BIG_ENDIAN;
    data->info.charsetFamily = U_CHARSET_FAMILY;
    data->info.sizeofUChar = sizeof(UChar);
    std::memcpy(data->info.dataFormat, "Brk ", 4);
    data->info.formatVersion[0] = 6;
    auto* header = reinterpret_cast<icu::RBBIDataHeader*>(bytes.data() + headerSize);
    header->fMagic = 0xb1a0;
    header->fFormatVersion[0] = 6;
    header->fLength = static_cast<std::uint32_t>(breakSize);
    header->fCatCount = 3;
    header->fTrie = sizeof(*header);
    header->fTrieLen = static_cast<std::uint32_t>(trie.size());
    std::memcpy(bytes.data() + headerSize + header->fTrie, trie.data(), trie.size());
    return bytes;
}

void CompareSwap(bool inPlace) {
    auto input = BreakData();
    UErrorCode openStatus = U_ZERO_ERROR;
    UDataSwapper* swapper = udata_openSwapper(U_IS_BIG_ENDIAN, U_CHARSET_FAMILY, !U_IS_BIG_ENDIAN,
                                              U_CHARSET_FAMILY, &openStatus);
    Expect(swapper != nullptr && openStatus == U_ZERO_ERROR, "swapper opens");
    std::vector<std::uint8_t> expected(input.size(), 0xa5);
    UErrorCode nativeStatus = U_ZERO_ERROR;
    const auto nativeResult = ubrk_swap(swapper, input.data(), static_cast<std::int32_t>(input.size()),
                                        expected.data(), &nativeStatus);
    std::int32_t guestStatus = U_ZERO_ERROR;
    auto actual = inPlace ? input : std::vector<std::uint8_t>(input.size(), 0xa5);
    const auto* guestInput = inPlace ? actual.data() : input.data();
    const auto guestResult = ubrk_swap_nid_postfix(swapper, guestInput, static_cast<std::int32_t>(input.size()),
                                                   actual.data(), &guestStatus);
    Expect(nativeResult == static_cast<std::int32_t>(input.size()) && guestResult == nativeResult,
           "swap returns the data length");
    Expect(nativeStatus == U_ZERO_ERROR && guestStatus == nativeStatus, "swap status matches ICU");
    Expect(actual == expected, "swapped data matches ICU");
    udata_closeSwapper(swapper);
}

void PreflightAndErrors() {
    auto input = BreakData();
    UErrorCode openStatus = U_ZERO_ERROR;
    UDataSwapper* swapper = udata_openSwapper(U_IS_BIG_ENDIAN, U_CHARSET_FAMILY, U_IS_BIG_ENDIAN,
                                              U_CHARSET_FAMILY, &openStatus);
    std::int32_t status = U_ZERO_ERROR;
    Expect(ubrk_swap_nid_postfix(swapper, input.data(), -1, nullptr, &status) ==
               static_cast<std::int32_t>(input.size()) && status == U_ZERO_ERROR,
           "preflight returns the data length");
    status = U_PARSE_ERROR;
    Expect(ubrk_swap_nid_postfix(nullptr, nullptr, -2, nullptr, &status) == 0 && status == U_PARSE_ERROR,
           "failing status returns before arguments");
    status = U_ZERO_ERROR;
    Expect(ubrk_swap_nid_postfix(nullptr, input.data(), -1, nullptr, &status) == 0 &&
               status == U_ILLEGAL_ARGUMENT_ERROR,
           "null swapper reports illegal argument");
    status = U_ZERO_ERROR;
    input[12] = 'X';
    Expect(ubrk_swap_nid_postfix(swapper, input.data(), -1, nullptr, &status) == 0 &&
               status == U_UNSUPPORTED_ERROR,
           "unknown data format is rejected");
    udata_closeSwapper(swapper);
}

}

int main() {
    CompareSwap(false);
    CompareSwap(true);
    PreflightAndErrors();
}
