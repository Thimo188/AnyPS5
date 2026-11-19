#include "prx/libSceIcu/libSceIcu.hpp"
#include "prx/libSceIcu/tests/RecoveredSignatureChecks.hpp"
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <type_traits>

namespace UresClose {

using IcuRecoveredTest::Require;

static_assert(std::is_same_v<decltype(&ures_close), void (APS5_VABI*)(UResourceBundle*)>);

namespace {

void RequireNonNullThrows(UResourceBundle* bundle) {
    try {
        ures_close(bundle);
    } catch (const std::runtime_error&) {
        return;
    }
    Require(false, "non-null UResourceBundle handle did not throw");
}

}

void Run() {
    UResourceBundle* bundle = nullptr;
    ures_close(bundle);
    for (int i = 0; i < 10; ++i) {
        ures_close(nullptr);
    }

    alignas(8) std::array<std::uint8_t, 64> storage{};
    storage.fill(0x5a);
    const auto expected = storage;
    RequireNonNullThrows(reinterpret_cast<UResourceBundle*>(storage.data()));
    Require(storage == expected, "non-null UResourceBundle handle was modified before the throw");
    RequireNonNullThrows(reinterpret_cast<UResourceBundle*>(static_cast<std::uintptr_t>(1)));
}

} // namespace UresClose

namespace UresResetIterator {

using IcuRecoveredTest::Require;

constexpr std::size_t BundleSize = 200;
constexpr std::size_t IndexOffset = 188;

static_assert(std::is_same_v<decltype(&ures_resetIterator_nid_postfix), void (APS5_VABI*)(UResourceBundle*)>);

void Reset(std::array<std::uint8_t, BundleSize>& storage) {
    ures_resetIterator_nid_postfix(reinterpret_cast<UResourceBundle*>(storage.data()));
}

void EverySurroundingByteValue() {
    for (std::uint32_t fill = 0; fill <= std::numeric_limits<std::uint8_t>::max(); ++fill) {
        std::array<std::uint8_t, BundleSize> storage{};
        storage.fill(static_cast<std::uint8_t>(fill));
        auto expected = storage;
        expected[IndexOffset] = 0xff;
        expected[IndexOffset + 1] = 0xff;
        expected[IndexOffset + 2] = 0xff;
        expected[IndexOffset + 3] = 0xff;
        Reset(storage);
        Require(storage == expected, "resource iterator reset changed bytes outside the ICU 68.2 index");
    }
}

void IndexValues() {
    constexpr std::array<std::int32_t, 6> values{
        std::numeric_limits<std::int32_t>::min(), -2, -1, 0, 1, std::numeric_limits<std::int32_t>::max()};
    for (const auto value : values) {
        std::array<std::uint8_t, BundleSize> storage{};
        std::memcpy(storage.data() + IndexOffset, &value, sizeof(value));
        Reset(storage);
        std::int32_t result = 0;
        std::memcpy(&result, storage.data() + IndexOffset, sizeof(result));
        Require(result == -1, "resource iterator index was not reset");
    }
}

void StackObject() {
    alignas(8) std::array<std::uint8_t, BundleSize> storage{};
    storage.fill(0x5a);
    auto* bundle = reinterpret_cast<UResourceBundle*>(storage.data());
    ures_initStackObject_nid_postfix(bundle);
    const std::int32_t previous = 19;
    std::memcpy(storage.data() + IndexOffset, &previous, sizeof(previous));
    ures_resetIterator_nid_postfix(bundle);
    std::int32_t result = 0;
    std::memcpy(&result, storage.data() + IndexOffset, sizeof(result));
    Require(result == -1, "stack resource iterator index was not reset");
}

void NullAndInvalid() {
    errno = ERANGE;
    ures_resetIterator_nid_postfix(nullptr);
    Require(errno == ERANGE, "null resource iterator reset changed errno");
    bool threw = false;
    try {
        ures_resetIterator_nid_postfix(reinterpret_cast<UResourceBundle*>(static_cast<std::uintptr_t>(1)));
    } catch (const std::runtime_error&) {
        threw = true;
    }
    Require(threw, "unwritable resource bundle did not throw");
}

void Errno() {
    std::array<std::uint8_t, BundleSize> storage{};
    errno = EDOM;
    Reset(storage);
    Require(errno == EDOM, "resource iterator reset changed errno");
}

void Run() {
    EverySurroundingByteValue();
    IndexValues();
    StackObject();
    NullAndInvalid();
    Errno();
}

} // namespace UresResetIterator

void CheckIcuResourceBundle() {
    UresClose::Run();
    UresResetIterator::Run();
}
