#include "vma.h"

#include <autoconf.h>
#include <memory/pmm/pmm.h>
#include <paging/paging.h>
#include <spinlock.h>
#include <util/util.h>

#include <stdio.h>
#include <string.h>

// @param phys optional parameter, maps the newly allocated virtual address to
// such physical address
void *vma_alloc(vmm_context_t *ctx, size_t pages, void *phys) {

    void *ptr = NULL;

    virtmem_object_t *cur_vmo = ctx->root_vmo;
    virtmem_object_t *new_vmo;

    for (; cur_vmo != NULL; cur_vmo = cur_vmo->next) {
#ifdef CONFIG_VMM_DEBUG
        debugf_debug("Checking for available memory\n");
        vmo_dump(cur_vmo);
#endif

        if ((cur_vmo->len >= pages) && (BIT_GET(cur_vmo->flags, 8) == 0)) {

#ifdef CONFIG_VMM_DEBUG
            debugf_debug("Well, we've got enough memory :D\n");
#endif
            break;
        }

#ifdef CONFIG_VMM_DEBUG
        debugf_debug("Current VMO is either too small or already "
                     "allocated. Skipping...\n");
#endif
        if (!cur_vmo->next) {
            uint64_t offset = (uint64_t)(cur_vmo->len * PFRAME_SIZE);
            new_vmo         = vmo_init(cur_vmo->base + offset, pages,
                                       cur_vmo->flags & ~(VMO_ALLOCATED));
            cur_vmo->next   = new_vmo;
            new_vmo->prev   = cur_vmo;
#ifdef CONFIG_VMM_DEBUG
            debugf_debug("VMO %p created successfully. Proceeding to next "
                         "iteration\n",
                         new_vmo);
#endif
        }
    }

    if (cur_vmo == NULL) {
        kprintf_panic("VMM ran out of memory and is not able to request it "
                      "from the PMM.\n");
        _hcf();
    }

    cur_vmo = split_vmo_at(cur_vmo, pages);
    FLAG_SET(cur_vmo->flags, VMO_ALLOCATED);

    ptr = (void *)(cur_vmo->base);

    void *phys_to_map = phys != NULL ? phys : pmm_alloc_pages(pages);
    map_region_to_page((uint64_t *)PHYS_TO_VIRTUAL(ctx->pml4_table),
                       (uint64_t)phys_to_map, (uint64_t)ptr,
                       (uint64_t)(pages * PFRAME_SIZE),
                       vmo_to_page_flags(cur_vmo->flags));

#ifdef CONFIG_VMM_DEBUG
    debugf_debug("Returning pointer %p\n", ptr);
#endif

    return ptr;
}

// @param free do you want to give back the physical address of `ptr` back to
// the PMM? (this will zero out that region on next allocation)
void vma_free(vmm_context_t *ctx, void *ptr, bool free) {

#ifdef CONFIG_VMM_DEBUG
    debugf_debug("Deallocating pointer %p\n", ptr);
#endif

    virtmem_object_t *cur_vmo = ctx->root_vmo;
    for (; cur_vmo != NULL; cur_vmo = cur_vmo->next) {
#ifdef CONFIG_VMM_DEBUG
        vmo_dump(cur_vmo);
#endif
        if ((uint64_t)ptr == cur_vmo->base) {
            break;
        }
#ifdef CONFIG_VMM_DEBUG
        debugf_debug("Pointer and vmo->base don't match. Skipping\n");
#endif
    }

    if (cur_vmo == NULL) {
#ifdef CONFIG_VMM_DEBUG
        debugf_debug(
            "Tried to deallocate a non-existing pointer. Quitting...\n");
#endif
        return;
    }

    FLAG_UNSET(cur_vmo->flags, VMO_ALLOCATED);

    // find the physical address of the VMO
    uint64_t phys = pg_virtual_to_phys(
        (uint64_t *)PHYS_TO_VIRTUAL(ctx->pml4_table), cur_vmo->base);
    if (free)
        pmm_free((void *)phys, cur_vmo->len);
    unmap_region((uint64_t *)PHYS_TO_VIRTUAL(ctx->pml4_table), cur_vmo->base,
                 (cur_vmo->len * PFRAME_SIZE));

    virtmem_object_t *to_dealloc = cur_vmo;
    virtmem_object_t *d_next     = to_dealloc->next;
    virtmem_object_t *d_prev     = to_dealloc->prev;

    if (cur_vmo == ctx->root_vmo) {
        ctx->root_vmo       = ctx->root_vmo->next;
        ctx->root_vmo->prev = NULL;
    } else {
        cur_vmo = d_next;
        if (d_next)
            d_next->prev = d_prev;
        if (d_prev)
            d_prev->next = d_next;
    }

#ifdef CONFIG_VMM_DEBUG
    debugf_debug("Region %llx destroyed\n", to_dealloc->base);
#endif

    size_t vmo_size_aligned = ROUND_UP(sizeof(virtmem_object_t), PFRAME_SIZE);
    pmm_free(to_dealloc, vmo_size_aligned / PFRAME_SIZE);
}
