#ifndef VMM_H
#define VMM_H 1

#include <limine.h>
#include <paging/paging.h>

#include <stddef.h>
#include <stdint.h>

// Virtual Memory Object
typedef struct vmo_t {
    uint64_t base;
    size_t len; // length is in pages (4KiB blocks)!!
    uint64_t flags;

    struct vmo_t *next;
    // struct virtmem_object_t *prev;
} vmo_t;

// Virtual Memory Context
typedef struct vmc_t {
    uint64_t *pml4_table;

    vmo_t *root_vmo;
} vmc_t;

// a linked list to track the address(es) to allocate for a VMO/VMM_CTX
typedef struct vmm_linkedlist {
    size_t len;
    struct vmm_linkedlist *next;
} vmm_node_t;

vmc_t *get_current_ctx();
void vmm_switch_ctx(vmc_t *new_ctx);

vmo_t *vmo_init(uint64_t base, size_t length, uint64_t flags);
void vmo_dump(vmo_t *vmo);
vmo_t *split_vmo_at(vmo_t *src_vmo, size_t len);

vmc_t *vmm_ctx_init(uint64_t *pml4, uint64_t flags);
void vmm_ctx_destroy(vmc_t *ctx);

void pagemap_copy_to(uint64_t *non_kernel_pml4);

void vmm_init(vmc_t *ctx);

void *valloc(vmc_t *ctx, size_t pages, uint8_t flags, void *phys);
void vfree(vmc_t *ctx, void *ptr, bool free);

#endif
