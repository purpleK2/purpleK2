#include "acpi/acpi.h"

#include <uacpi/uacpi.h>

int uacpi_init() {
    uacpi_status ret = uacpi_initialize(0);
    if (uacpi_likely_error(ret)) {
        uacpi_kernel_log(UACPI_LOG_ERROR,
                         "Couldn't initialize basic ACPI components!\n");

        return -1;
    }

    return 0;
}
