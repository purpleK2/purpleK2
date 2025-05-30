#include "madt.h"

#include <cpu.h>
#include <kernel.h>
#include <memory/heap/kheap.h>
#include <uacpi/acpi.h>
#include <uacpi/tables.h>
#include <uacpi/uacpi.h>

#include <stddef.h>
#include <stdio.h>
#include <string.h>

void *madt_find_record(void *madt, int record_type) {
    void *addr = (madt + MADT_RECORD_OFFSET);

    for (; addr < ((void *)madt + ((struct acpi_madt *)madt)->hdr.length);) {
        struct acpi_entry_hdr *record_header = (struct acpi_entry_hdr *)(addr);

        if (record_header->type == record_type) {
            return (void *)record_header;
        }

        addr += record_header->length;
    }

    return NULL;
}