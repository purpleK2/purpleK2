#ifndef VMM_H
#define VMM_H 1

#include <limine.h>
#include <paging/paging.h>

#include <stddef.h>
#include <stdint.h>

struct vnode; // forward declaration for file-backed mmap

// Virtual Memory Object
typedef struct vmo_t {
    uint64_t base;
    size_t len; // length is in pages (4KiB blocks)!!
    uint64_t flags;

    struct vnode *backing_vnode;
    size_t file_offset;

    struct vmo_t *next;
} vmo_t;

// Virtual Memory Context
typedef struct vmc_t {
    uint64_t *pml4_table;

    vmo_t *root_vmo;
} vmc_t;

// a linked list to track the address(es) to allocate for a VMO/VMM_CTX
typedef struct vmm_linkedlist {
    size_t len; // length in bytes
    struct vmm_linkedlist *next;
} vmm_node_t;

vmc_t *get_current_vmc();
void vmc_switch(vmc_t *new_ctx);

void set_kernel_vmc(vmc_t *kvmc);
vmc_t *get_kernel_vmc();

vmc_t *get_global_vmc();
void set_global_vmc(vmc_t *glob);

vmc_t *vmc_alloc();
void vmc_free(vmc_t *v);

vmo_t *vmo_alloc();
void vmo_free(vmo_t *v);

vmo_t *vmo_init(uint64_t base, size_t length, uint64_t flags);
void vmo_dump(vmo_t *vmo);
vmo_t *split_vmo_at(vmo_t *src_vmo, size_t len);

vmc_t *vmc_init(uint64_t *pml4, uint64_t flags);
void vmc_destroy(vmc_t *ctx);

// Create a new VM context that shares pages with the parent using COW
vmc_t *vmc_fork(vmc_t *parent);

void pagemap_copy_to(uint64_t *non_kernel_pml4);

void vmm_init(vmc_t *ctx);
void process_vmm_init(vmc_t **proc_vmcr, uint64_t flags);

void *valloc(vmc_t *ctx, size_t pages, uint8_t flags, void *phys);
void *valloc_at(vmc_t *ctx, void *addr, size_t pages, uint8_t flags, void *phys);
void *valloc_at_lazy(vmc_t *ctx, void *addr, size_t pages, uint8_t flags,
                     struct vnode *vnode, size_t file_offset);
vmo_t *vmo_find_by_addr(vmc_t *vmc, uint64_t addr);
void vfree(vmc_t *ctx, void *ptr, bool free);

void global_vmc_init(vmc_t *kernel_vmc);

#endif
