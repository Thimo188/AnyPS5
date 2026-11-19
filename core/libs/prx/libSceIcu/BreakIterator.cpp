#include "prx/libSceIcu/BreakIterator.hpp"
#include "prx/libc/include/General.hpp"
#include "unicode/ubrk.h"
#include "unicode/uenum.h"
#include "unicode/uloc.h"
#include <cerrno>
#include <stdexcept>
#include <string>

#undef ubrk_open
#undef ubrk_close
#undef ubrk_setText
#undef ubrk_first
#undef ubrk_last
#undef ubrk_next
#undef ubrk_previous
#undef ubrk_current
#undef ubrk_following
#undef ubrk_preceding
#undef ubrk_isBoundary
#undef ubrk_getRuleStatus
#undef ubrk_safeClone
#undef ubrk_countAvailable
#undef ubrk_getAvailable

namespace {

std::int32_t ReadGuestInt(const std::int32_t* source, const char* function) {
    std::int32_t value = 0;
    const int savedErrno = errno;
    const bool copied = GuestCopyIn_nid_no_patch(&value, source, sizeof(value));
    errno = savedErrno;
    if (!copied) throw std::invalid_argument(std::string(function) + ": unreadable argument");
    return value;
}

void WriteGuestInt(std::int32_t* destination, std::int32_t value, const char* function) {
    const int savedErrno = errno;
    const bool copied = GuestCopyOut_nid_no_patch(destination, &value, sizeof(value));
    errno = savedErrno;
    if (!copied) throw std::invalid_argument(std::string(function) + ": unwritable argument");
}

}

extern "C" {

void* APS5_VABI ubrk_open(std::int32_t type, const char* locale, const char16_t* text, std::int32_t length,
                         std::int32_t* error) {
    if (!error) APS5_INVALID_ARG_EX;
    auto status = static_cast<UErrorCode>(*error);
    auto* result = ubrk_open_78(static_cast<UBreakIteratorType>(type), locale, text, length, &status);
    *error = status;
    return result;
}

void APS5_VABI ubrk_close(void* iterator) {
    ubrk_close_78(static_cast<UBreakIterator*>(iterator));
}

void APS5_VABI ubrk_setText(void* iterator, const char16_t* text, std::int32_t length, std::int32_t* error) {
    if (!iterator || !error) APS5_INVALID_ARG_EX;
    auto status = static_cast<UErrorCode>(*error);
    ubrk_setText_78(static_cast<UBreakIterator*>(iterator), text, length, &status);
    *error = status;
}

std::int32_t APS5_VABI ubrk_first(void* iterator) {
    if (!iterator) APS5_INVALID_ARG_EX;
    return ubrk_first_78(static_cast<UBreakIterator*>(iterator));
}

std::int32_t APS5_VABI ubrk_last(void* iterator) {
    if (!iterator) APS5_INVALID_ARG_EX;
    return ubrk_last_78(static_cast<UBreakIterator*>(iterator));
}

std::int32_t APS5_VABI ubrk_next(void* iterator) {
    if (!iterator) APS5_INVALID_ARG_EX;
    return ubrk_next_78(static_cast<UBreakIterator*>(iterator));
}

std::int32_t APS5_VABI ubrk_previous(void* iterator) {
    if (!iterator) APS5_INVALID_ARG_EX;
    return ubrk_previous_78(static_cast<UBreakIterator*>(iterator));
}

std::int32_t APS5_VABI ubrk_current(const void* iterator) {
    if (!iterator) APS5_INVALID_ARG_EX;
    return ubrk_current_78(static_cast<const UBreakIterator*>(iterator));
}

std::int32_t APS5_VABI ubrk_following(void* iterator, std::int32_t offset) {
    if (!iterator) APS5_INVALID_ARG_EX;
    return ubrk_following_78(static_cast<UBreakIterator*>(iterator), offset);
}

std::int32_t APS5_VABI ubrk_preceding(void* iterator, std::int32_t offset) {
    if (!iterator) APS5_INVALID_ARG_EX;
    return ubrk_preceding_78(static_cast<UBreakIterator*>(iterator), offset);
}

std::int8_t APS5_VABI ubrk_isBoundary(void* iterator, std::int32_t offset) {
    if (!iterator) APS5_INVALID_ARG_EX;
    return ubrk_isBoundary_78(static_cast<UBreakIterator*>(iterator), offset);
}

std::int32_t APS5_VABI ubrk_getRuleStatus(void* iterator) {
    if (!iterator) APS5_INVALID_ARG_EX;
    return ubrk_getRuleStatus_78(static_cast<UBreakIterator*>(iterator));
}

UBreakIterator* APS5_VABI ubrk_safeClone_nid_postfix(
    const UBreakIterator* iterator, void*, std::int32_t* bufferSize, std::int32_t* status) {
    if (!status) return nullptr;
    const auto incoming = ReadGuestInt(status, __func__);
    if (incoming > 0) return nullptr;
    auto localStatus = static_cast<UErrorCode>(incoming);
    if (!iterator) {
        auto* result = ubrk_safeClone_78(nullptr, nullptr, nullptr, &localStatus);
        if (localStatus != incoming) WriteGuestInt(status, localStatus, __func__);
        return result;
    }
    std::int32_t localSize = 0;
    std::int32_t* size = nullptr;
    if (bufferSize) {
        localSize = ReadGuestInt(bufferSize, __func__);
        WriteGuestInt(bufferSize, 1, __func__);
        if (localSize == 0) return nullptr;
        size = &localSize;
    }
    auto* result = ubrk_safeClone_78(iterator, nullptr, size, &localStatus);
    if (localStatus != incoming) {
        try {
            WriteGuestInt(status, localStatus, __func__);
        } catch (...) {
            ubrk_close_78(result);
            throw;
        }
    }
    return result;
}

std::int32_t APS5_VABI ubrk_countAvailable() {
    return ubrk_countAvailable_78();
}

const char* APS5_VABI ubrk_getAvailable(std::int32_t index) {
    const auto count = ubrk_countAvailable_78();
    if (index < 0 || index == count) {
        if (count > 0) APS5_INVALID_ARG_EX;
        UErrorCode status = U_ZERO_ERROR;
        auto* available = uloc_openAvailableByType(ULOC_AVAILABLE_DEFAULT, &status);
        uenum_close(available);
        if (U_SUCCESS(status)) APS5_INVALID_ARG_EX;
    }
    return ubrk_getAvailable_78(index);
}

}
