#ifndef ACPI_ARCH_HELPERS_H
#define ACPI_ARCH_HELPERS_H 1

#include <acpi/uacpi/types.h>
#include <stdint.h>

void uacpi_register_handler(uint32_t irq, uacpi_handle ctx,
                            uacpi_interrupt_handler handler);

void uacpi_unregister_handler(uint32_t irq);

#endif