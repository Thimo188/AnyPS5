#include "prx/libSceIcu/BreakIterator.hpp"
#include "prx/libc/include/General.hpp"
#include "unicode/ubrk.h"
#include "unicode/uenum.h"
#include "unicode/uloc.h"
#include <algorithm>
#include <cerrno>
#include <stdexcept>
#include <string>
#include <vector>

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
#undef ubrk_getRuleStatusVec
#undef ubrk_countAvailable
#undef ubrk_getAvailable

namespace {

std::int32_t ReadStatus(const std::int32_t* status, const char* caller) {
    if (!status) throw std::invalid_argument(std::string(caller) + ": invalid argument");
    std::int32_t value = 0;
    const int savedErrno = errno;
    const bool readable = GuestCopyIn_nid_no_patch(&value, status, sizeof(value));
    errno = savedErrno;
    if (!readable) throw std::invalid_argument(std::string(caller) + ": unreadable status");
    return value;
}

void WriteStatus(std::int32_t* status, std::int32_t incoming, std::int32_t outgoing, const char* caller) {
    if (outgoing == incoming) return;
    const int savedErrno = errno;
    const bool writable = GuestCopyOut_nid_no_patch(status, &outgoing, sizeof(outgoing));
    errno = savedErrno;
    if (!writable) throw std::invalid_argument(std::string(caller) + ": unwritable status");
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

std::int32_t APS5_VABI ubrk_getRuleStatusVec_nid_postfix(
    UBreakIterator* iterator, std::int32_t* fillInVec, std::int32_t capacity, std::int32_t* status) {
    const auto incoming = ReadStatus(status, __func__);
    if (incoming > 0) return 0;
    if (!iterator || (!fillInVec && capacity > 0)) APS5_INVALID_ARG_EX;
    auto local = static_cast<UErrorCode>(incoming);
    const auto count = ubrk_getRuleStatusVec_78(iterator, nullptr, 0, &local);
    if (count <= 0) {
        WriteStatus(status, incoming, local, __func__);
        return count;
    }
    std::vector<std::int32_t> values(static_cast<std::size_t>(count));
    local = static_cast<UErrorCode>(incoming);
    const auto result = ubrk_getRuleStatusVec_78(iterator, values.data(), count, &local);
    const auto copied = (std::min)((std::max)(capacity, 0), result);
    if (copied > 0) {
        const int savedErrno = errno;
        const bool writable = GuestCopyOut_nid_no_patch(fillInVec, values.data(), static_cast<std::size_t>(copied) * sizeof(values[0]));
        errno = savedErrno;
        if (!writable) throw std::invalid_argument(std::string(__func__) + ": unwritable output");
    }
    if (capacity < result) local = U_BUFFER_OVERFLOW_ERROR;
    WriteStatus(status, incoming, local, __func__);
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
