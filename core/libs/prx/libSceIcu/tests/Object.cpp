#include "prx/libSceIcu/include/LegacyExports.hpp"
#include "unicode/uobject.h"
#include <cstdio>
#include <cstdlib>
#include <source_location>
#include <type_traits>

static_assert(std::is_same_v<decltype(&uprv_deleteUObject_nid_postfix), void (APS5_VABI*)(void*)>);

namespace {

void Require(bool value, std::source_location location = std::source_location::current()) {
    if (value) return;
    std::fprintf(stderr, "ICU object deletion check failed at line %u\n", location.line());
    std::abort();
}

class Tracked final : public icu::UObject {
public:
    explicit Tracked(int* destructions) : destructions_(destructions) {}
    ~Tracked() override { ++*destructions_; }

private:
    int* destructions_;
};

}

int main() {
    int destructions = 0;
    uprv_deleteUObject_nid_postfix(nullptr);
    Require(destructions == 0);
    uprv_deleteUObject_nid_postfix(new Tracked(&destructions));
    Require(destructions == 1);
    uprv_deleteUObject_nid_postfix(new Tracked(&destructions));
    Require(destructions == 2);
}
