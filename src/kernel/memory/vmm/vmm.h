#ifndef VMM_H
#define VMM_H 1

#include <limine.h>
#include <paging/paging.h>

#include <stddef.h>
#include <stdint.h>

typedef struct virtmem_object_t {
    uint64_t base;
    size_t len; // length is in pages (4KiB blocks)!!
    uint64_t flags;

    struct virtmem_object_t *next;
    struct virtmem_object_t *prev;
} virtmem_object_t;

typedef struct vmm_context_t {
    uint64_t *pml4_table;

    virtmem_object_t *root_vmo;
} vmm_context_t;

vmm_context_t *get_current_ctx();
void vmm_switch_ctx(vmm_context_t *new_ctx);

virtmem_object_t *vmo_init(uint64_t base, size_t length, uint64_t flags);
void vmo_dump(virtmem_object_t *vmo);
virtmem_object_t *split_vmo_at(virtmem_object_t *src_vmo, size_t len);

vmm_context_t *vmm_ctx_init(uint64_t *pml4, uint64_t flags);
void vmm_ctx_destroy(vmm_context_t *ctx);

void pagemap_copy_to(uint64_t *non_kernel_pml4);

void vmm_init(vmm_context_t *ctx);

#endif
