#ifndef VMA_H
#define VMA_H 1

#include <memory/vmm/vmm.h>

#include <stdbool.h>
#include <stdint.h>

void *valloc(vmm_context_t *ctx, size_t pages, uint8_t flags, void *phys);
void vfree(vmm_context_t *ctx, void *ptr, bool free);

#endif