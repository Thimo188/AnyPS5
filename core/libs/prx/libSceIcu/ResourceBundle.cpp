// © 2016 and later: Unicode, Inc. and others.
// License & terms of use: http://www.unicode.org/copyright.html
/*
******************************************************************************
* Copyright (C) 1997-2016, International Business Machines Corporation and
* others. All Rights Reserved.
******************************************************************************
*/
// https://github.com/unicode-org/icu/blob/84e1f26ea77152936e70d53178a816dbfbf69989/icu4c/source/common/uresbund.cpp

#include "prx/libSceIcu/RecoveredSignatures.hpp"
#include "prx/libc/include/General.hpp"
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

namespace {

constexpr std::size_t Icu68ResourceBundleSize = 200;

struct ResourceData68 {
    void* data;
    const std::int32_t* root;
    const std::uint16_t* units;
    const char* poolKeys;
    std::uint32_t rootResource;
    std::int32_t localKeyLimit;
    const std::uint16_t* poolStrings;
    std::int32_t poolStringLimit;
    std::int32_t poolString16Limit;
    std::int8_t noFallback;
    std::int8_t isPool;
    std::int8_t usesPool;
    std::int8_t nativeComparison;
};

struct ResourceBundle68 {
    const char* key;
    void* data;
    char* version;
    void* topLevelData;
    char* path;
    ResourceData68 resourceData;
    char resourceBuffer[64];
    std::int32_t pathLength;
    std::uint32_t resource;
    std::int8_t hasFallback;
    std::int8_t isTopLevel;
    std::uint32_t firstMagic;
    std::uint32_t secondMagic;
    std::int32_t index;
    std::int32_t size;
};

static_assert(sizeof(ResourceData68) == 64);
static_assert(offsetof(ResourceBundle68, index) == 188);
static_assert(sizeof(ResourceBundle68) == 200);

constexpr std::size_t ResourceIndexOffset = offsetof(ResourceBundle68, index);

}

extern "C" {

void APS5_VABI ures_close(UResourceBundle* resB) {
    if (!resB) {
        return;
    }
    NotImplemented_nid_no_patch(__func__);
}

void APS5_VABI ures_initStackObject_nid_postfix(UResourceBundle* resB) {
    std::memset(resB, 0, Icu68ResourceBundleSize);
}

void APS5_VABI ures_resetIterator_nid_postfix(UResourceBundle* resourceBundle) {
    if (!resourceBundle) return;
    const auto base = reinterpret_cast<std::uintptr_t>(resourceBundle);
    if (base > std::numeric_limits<std::uintptr_t>::max() - ResourceIndexOffset) {
        NotImplemented_nid_no_patch(__func__);
    }
    const std::int32_t index = -1;
    const int savedErrno = errno;
    const bool copied = GuestCopyOut_nid_no_patch(reinterpret_cast<void*>(base + ResourceIndexOffset), &index, sizeof(index));
    errno = savedErrno;
    if (!copied) NotImplemented_nid_no_patch(__func__);
}

}
