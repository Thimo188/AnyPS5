#include "prx/libSceIcu/include/LegacyExports.hpp"
#include "cmemory.h"

extern "C" {

void APS5_VABI uprv_deleteUObject_nid_postfix(void* object) {
    uprv_deleteUObject(object);
}

}
