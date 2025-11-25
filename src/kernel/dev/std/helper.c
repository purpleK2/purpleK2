#include "helper.h"

#include <dev/std/null/null.h>

void register_std_devices() {
    dev_null_init();
}