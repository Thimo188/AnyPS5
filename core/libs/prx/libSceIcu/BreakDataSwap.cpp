#include "prx/libSceIcu/include/LegacyExports.hpp"
#include "prx/libc/include/General.hpp"
#include "rbbidata.h"
#include "ucmndata.h"
#include "udataswp.h"
#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <vector>

namespace {

class PreservedErrno {
public:
    PreservedErrno() : saved(errno) {}
    ~PreservedErrno() { errno = saved; }

private:
    int saved;
};

bool CopyIn(void* destination, const void* source, std::size_t size) {
    PreservedErrno guard;
    return GuestCopyIn_nid_no_patch(destination, source, size);
}

bool CopyOut(void* destination, const void* source, std::size_t size) {
    PreservedErrno guard;
    return GuestCopyOut_nid_no_patch(destination, source, size);
}

void RequireCopy(bool copied, const char* caller) {
    if (!copied) NotImplemented_nid_no_patch(caller);
}

struct SwapperTraits {
    std::int8_t inputBigEndian;
    std::uint8_t inputCharset;
    std::int8_t outputBigEndian;
    std::uint8_t outputCharset;
};

using SwapperOwner = std::unique_ptr<UDataSwapper, decltype(&udata_closeSwapper)>;

std::uint32_t Read32(const UDataSwapper* swapper, const void* source) {
    std::uint32_t value = 0;
    std::memcpy(&value, source, sizeof(value));
    return swapper->readUInt32(value);
}

std::uint16_t Read16(const UDataSwapper* swapper, const void* source) {
    std::uint16_t value = 0;
    std::memcpy(&value, source, sizeof(value));
    return swapper->readUInt16(value);
}

std::size_t CheckedAdd(std::size_t left, std::size_t right, const char* caller) {
    if (right > static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max()) - left)
        NotImplemented_nid_no_patch(caller);
    return left + right;
}

bool Range(std::uint32_t offset, std::uint32_t size, std::uint32_t limit) {
    return offset <= limit && size <= limit - offset;
}

void ValidateBreakData(const UDataSwapper* swapper, const std::uint8_t* bytes, std::uint32_t length,
                       const char* caller) {
    const auto* header = reinterpret_cast<const icu::RBBIDataHeader*>(bytes);
    const auto field = [&](const std::uint32_t& value) { return swapper->readUInt32(value); };
    const auto requireRange = [&](const std::uint32_t& offset, const std::uint32_t& size) {
        if (!Range(field(offset), field(size), length)) NotImplemented_nid_no_patch(caller);
    };
    requireRange(header->fFTable, header->fFTableLen);
    requireRange(header->fRTable, header->fRTableLen);
    requireRange(header->fTrie, header->fTrieLen);
    requireRange(header->fRuleSource, header->fRuleSourceLen);
    requireRange(header->fStatusTable, header->fStatusTableLen);
    const auto tableHeader = static_cast<std::uint32_t>(offsetof(icu::RBBIStateTable, fTableData));
    if ((field(header->fFTableLen) != 0 && field(header->fFTableLen) < tableHeader) ||
        (field(header->fRTableLen) != 0 && field(header->fRTableLen) < tableHeader) ||
        field(header->fTrieLen) < 16 || (field(header->fStatusTableLen) & 3) != 0)
        NotImplemented_nid_no_patch(caller);
}

}

extern "C" {

std::int32_t APS5_VABI ubrk_swap_nid_postfix(const UDataSwapper* guestSwapper, const void* guestInput,
                                              std::int32_t length, void* guestOutput, std::int32_t* guestStatus) {
    if (!guestStatus) return 0;
    std::int32_t previous = 0;
    RequireCopy(CopyIn(&previous, guestStatus, sizeof(previous)), __func__);
    if (previous > 0) return 0;
    UErrorCode status = static_cast<UErrorCode>(previous);
    const auto leave = [&] {
        const auto updated = static_cast<std::int32_t>(status);
        if (updated != previous) RequireCopy(CopyOut(guestStatus, &updated, sizeof(updated)), __func__);
    };
    if (!guestSwapper || !guestInput || length < -1 || (length > 0 && !guestOutput)) {
        status = U_ILLEGAL_ARGUMENT_ERROR;
        leave();
        return 0;
    }
    SwapperTraits traits{};
    RequireCopy(CopyIn(&traits, guestSwapper, sizeof(traits)), __func__);
    UErrorCode openStatus = U_ZERO_ERROR;
    SwapperOwner swapper(udata_openSwapper(traits.inputBigEndian, traits.inputCharset, traits.outputBigEndian,
                                           traits.outputCharset, &openStatus), &udata_closeSwapper);
    if (U_FAILURE(openStatus) || !swapper) {
        status = openStatus;
        leave();
        return 0;
    }

    constexpr std::size_t formatProbeSize = offsetof(DataHeader, info) + offsetof(UDataInfo, dataVersion);
    std::vector<std::uint8_t> input(formatProbeSize);
    RequireCopy(CopyIn(input.data(), guestInput, input.size()), __func__);
    const auto* info = reinterpret_cast<const UDataInfo*>(input.data() + sizeof(MappedData));
    const bool dataFormat = std::memcmp(info->dataFormat, "Brk ", 4) == 0 && info->formatVersion[0] == 6;
    if (!dataFormat) {
        std::uint8_t output = 0;
        const auto result = ubrk_swap(swapper.get(), input.data(), length, length > 0 ? &output : nullptr, &status);
        leave();
        return result;
    }
    const std::size_t headerSize = Read16(swapper.get(), input.data());
    const std::size_t prefixSize = CheckedAdd(headerSize, sizeof(icu::RBBIDataHeader), __func__);
    input.resize(prefixSize);
    RequireCopy(CopyIn(input.data(), guestInput, input.size()), __func__);

    std::size_t totalSize = prefixSize;
    bool validBreakHeader = false;
    const auto* breakHeader = reinterpret_cast<const icu::RBBIDataHeader*>(input.data() + headerSize);
    const auto breakLength = Read32(swapper.get(), &breakHeader->fLength);
    validBreakHeader = Read32(swapper.get(), &breakHeader->fMagic) == 0xb1a0 &&
        breakHeader->fFormatVersion[0] == 6 && breakLength >= sizeof(icu::RBBIDataHeader);
    if (validBreakHeader) totalSize = CheckedAdd(headerSize, breakLength, __func__);
    if (validBreakHeader && length >= 0 && static_cast<std::size_t>(length) >= totalSize) {
        input.resize(totalSize);
        RequireCopy(CopyIn(input.data(), guestInput, input.size()), __func__);
        ValidateBreakData(swapper.get(), input.data() + headerSize,
                          static_cast<std::uint32_t>(totalSize - headerSize), __func__);
    }

    std::size_t outputSize = 0;
    if (length > 0) {
        outputSize = std::min<std::size_t>(static_cast<std::size_t>(length), std::max(headerSize, totalSize));
    }
    const bool inPlace = guestInput == guestOutput;
    std::vector<std::uint8_t> output;
    void* nativeOutput = nullptr;
    if (length > 0) {
        if (inPlace) {
            if (input.size() < outputSize) input.resize(outputSize);
            nativeOutput = input.data();
        } else {
            output.resize(outputSize);
            RequireCopy(CopyIn(output.data(), guestOutput, output.size()), __func__);
            nativeOutput = output.data();
        }
    }
    const auto result = ubrk_swap(swapper.get(), input.data(), length, nativeOutput, &status);
    if (length > 0) {
        const auto* bytes = inPlace ? input.data() : output.data();
        RequireCopy(CopyOut(guestOutput, bytes, outputSize), __func__);
    }
    leave();
    return result;
}

}
