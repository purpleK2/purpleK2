#include "vmm.h"

#include <autoconf.h>
#include <cpu.h>
#include <kernel.h>

#include "vflags.h"
#include <paging/paging.h>

#include <spinlock.h>

#include <util/util.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

vmm_context_t *current_vmm_ctx;

vmm_context_t *get_current_ctx() {
    return current_vmm_ctx;
}

void vmm_switch_ctx(vmm_context_t *new_ctx) {
    current_vmm_ctx = new_ctx;
}

// imagine making a function to print stuff that you're going to barely use LMAO
void vmo_dump(virtmem_object_t *vmo) {
    /*debugf_debug("VMO %p\n", vmo);
    debugf_debug("\tprev: %p\n", vmo->prev);
    debugf_debug("\tbase: %llx\n", vmo->base);
    debugf_debug("\tlen %zu\n", vmo->len);
    debugf_debug("\tflags: %llb\n", vmo->flags);
    debugf_debug("\tnext: %p\n", vmo->next);*/
}

// @param length IT'S IN PAGESSSS
virtmem_object_t *vmo_init(uint64_t base, size_t length, uint64_t flags) {

    size_t vmosize_aligned = ROUND_UP(sizeof(virtmem_object_t), PFRAME_SIZE);
    virtmem_object_t *vmo  = (virtmem_object_t *)PHYS_TO_VIRTUAL(
        pmm_alloc_pages(vmosize_aligned / PFRAME_SIZE));

    vmo->base  = base;
    vmo->len   = length;
    vmo->flags = flags;

    vmo->next = NULL;
    vmo->prev = NULL;

    return vmo;
}

// @note We will not care if `pml4` is 0x0 :^)
vmm_context_t *vmm_ctx_init(uint64_t *pml4, uint64_t flags) {

    size_t vmcsize_aligned = ROUND_UP(sizeof(virtmem_object_t), PFRAME_SIZE);
    vmm_context_t *ctx     = (vmm_context_t *)PHYS_TO_VIRTUAL(
        pmm_alloc_pages(vmcsize_aligned / PFRAME_SIZE));

    /*
    For some reason UEFI gives out region 0x0-0x1000 as usable :/
    if (pml4 == NULL) {
        pml4 = (uint64_t *)PHYS_TO_VIRTUAL(pmm_alloc_page());
    }
    */

    ctx->pml4_table = pml4;
    ctx->root_vmo   = vmo_init(0x1000, 1, flags);

    return ctx;
}

void vmm_ctx_destroy(vmm_context_t *ctx) {

    if (VIRT_TO_PHYSICAL(ctx->pml4_table) == (uint64_t)cpu_get_cr(3)) {
        kprintf_warn("Attempted to destroy a pagemap that's currently in use. "
                     "Skipping\n");
        return;
    }

    // Free all VMOs and their associated physical memory
    for (virtmem_object_t *i = ctx->root_vmo; i != NULL;) {
        virtmem_object_t *next = i->next;

        // Only free physical memory if the VMO is mapped
        if (i->flags & VMO_PRESENT) {
            uint64_t phys = pg_virtual_to_phys(ctx->pml4_table, i->base);
            if (phys) {
                pmm_free((void *)PHYS_TO_VIRTUAL(phys), i->len);
            }
        }

        // Free the VMO structure itself
        pmm_free(i,
                 ROUND_UP(sizeof(virtmem_object_t), PFRAME_SIZE) / PFRAME_SIZE);
        i = next;
    }

    // Unmap all pages in the page tables
    for (int pml4_idx = 0; pml4_idx < 512; pml4_idx++) {
        uint64_t *pml4 = (uint64_t *)PHYS_TO_VIRTUAL(ctx->pml4_table);
        if (!(pml4[pml4_idx] & PMLE_PRESENT)) {
            continue;
        }

        uint64_t *pdpt = (uint64_t *)PHYS_TO_VIRTUAL(pml4[pml4_idx] & ~0xFFF);
        for (int pdpt_idx = 0; pdpt_idx < 512; pdpt_idx++) {
            if (!(pdpt[pdpt_idx] & PMLE_PRESENT)) {
                continue;
            }

            uint64_t *pd = (uint64_t *)PHYS_TO_VIRTUAL(pdpt[pdpt_idx] & ~0xFFF);
            for (int pd_idx = 0; pd_idx < 512; pd_idx++) {
                if (!(pd[pd_idx] & PMLE_PRESENT)) {
                    continue;
                }

                uint64_t *pt = (uint64_t *)PHYS_TO_VIRTUAL(pd[pd_idx] & ~0xFFF);

                // Free the page table
                pmm_free((void *)pt, 1);
            }

            // Free the page directory
            pmm_free((void *)pd, 1);
        }

        // Free the PDPT
        pmm_free((void *)pdpt, 1);
    }

    // Free the PML4 table and the context
    pmm_free(ctx->pml4_table, 1);
    size_t vmcsize_aligned = ROUND_UP(sizeof(virtmem_object_t), PFRAME_SIZE);
    pmm_free(ctx, vmcsize_aligned / PFRAME_SIZE);

    ctx->pml4_table = NULL;
}

// @param where after how many pages should we split the VMO
virtmem_object_t *split_vmo_at(virtmem_object_t *src_vmo, size_t where) {
    virtmem_object_t *new_vmo;

    if (src_vmo->len - where <= 0) {
        return src_vmo; // we are not going to split it
    }

    size_t offset = (uint64_t)(where * PFRAME_SIZE);
    new_vmo =
        vmo_init(src_vmo->base + offset, src_vmo->len - where, src_vmo->flags);
    /*
    src_vmo		  new_vmo
    [     [                        ]
    0	  0+len					   X
    */
    /*debugf_debug("VMO %p has been split at (virt)%llx\n", src_vmo,
                 src_vmo->base + offset);*/

    src_vmo->len = where;

    if (src_vmo->next != NULL) {
        new_vmo->next = src_vmo->next;
        src_vmo->next = new_vmo;
        new_vmo->prev = src_vmo;
    }

    /*
    src_vmo		  new_vmo
    [     ]<-->[                        ]-->...
    0	       0+len					X
    */

    return src_vmo;
}

void pagemap_copy_to(uint64_t *non_kernel_pml4) {

    uint64_t *k_pml4 = (uint64_t *)PHYS_TO_VIRTUAL(get_kernel_pml4());

    if ((uint64_t *)PHYS_TO_VIRTUAL(non_kernel_pml4) == k_pml4)
        return;

    for (int i = 0; i < 512; i++) {
        // debugf("Copying %p[%d](%llx) to %p[%d]\n", k_pml4, i, k_pml4[i],
        //        non_kernel_pml4, i);

        ((uint64_t *)PHYS_TO_VIRTUAL(non_kernel_pml4))[i] = k_pml4[i];
    }
}

// Assumes the CTX has been initialized with vmm_ctx_init()
void vmm_init(vmm_context_t *ctx) {
    for (virtmem_object_t *i = ctx->root_vmo; i != NULL; i = i->next) {
        // every VMO will have the same flags as the root one
        i->flags = ctx->root_vmo->flags;

        // mapping will be done on vma_alloc
    }

    pagemap_copy_to(ctx->pml4_table);
}

void *valloc(vmm_context_t *ctx, size_t pages, uint8_t flags, void *phys) {

    void *ptr = NULL;

    virtmem_object_t *cur_vmo = ctx->root_vmo;
    virtmem_object_t *new_vmo;

    for (; cur_vmo != NULL; cur_vmo = cur_vmo->next) {
        // debugf_debug("Checking for available memory\n");
        vmo_dump(cur_vmo);

        if ((cur_vmo->len >= pages) && (BIT_GET(cur_vmo->flags, 8) == 0)) {

            // debugf_debug("Well, we've got enough memory :D\n");
            break;
        }

        // debugf_debug("Current VMO is either too small or already "
        //              "allocated. Skipping...\n");
        if (!cur_vmo->next) {
            uint64_t offset = (uint64_t)(cur_vmo->len * PFRAME_SIZE);
            new_vmo         = vmo_init(cur_vmo->base + offset, pages,
                                       flags & ~(VMO_ALLOCATED));
            cur_vmo->next   = new_vmo;
            new_vmo->prev   = cur_vmo;
            // debugf_debug("VMO %p created successfully. Proceeding to next "
            //              "iteration\n",
            //             new_vmo);
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

    void *phys_al = NULL;
    size_t offset = 0;
    if (phys) {
        phys_al = (void *)ROUND_DOWN((size_t)phys, PFRAME_SIZE);
        offset  = (size_t)(phys_al - phys);
    }

    void *phys_to_map = phys_al ? phys_al : pmm_alloc_pages(pages);
    map_region_to_page((uint64_t *)PHYS_TO_VIRTUAL(ctx->pml4_table),
                       (uint64_t)phys_to_map, (uint64_t)ptr,
                       (uint64_t)(pages * PFRAME_SIZE),
                       vmo_to_page_flags(flags));

    // debugf_debug("Returning pointer %p\n", ptr);

    return (ptr + offset);
}

// @param free do you want to give back the physical address of `ptr` back to
// the PMM? (this will zero out that region on next allocation)
void vfree(vmm_context_t *ctx, void *ptr, bool free) {

#ifdef CONFIG_VMM_DEBUG
    debugf_debug("Deallocating pointer %p\n", ptr);
#endif

    ptr = (void *)ROUND_DOWN((uint64_t)ptr, PFRAME_SIZE);

    virtmem_object_t *cur_vmo = ctx->root_vmo;
    for (; cur_vmo != NULL; cur_vmo = cur_vmo->next) {
        vmo_dump(cur_vmo);
        if ((uint64_t)ptr == cur_vmo->base) {
            break;
        }
        // debugf_debug("Pointer and vmo->base don't match. Skipping\n");
    }

    if (cur_vmo == NULL) {
        // debugf_debug(
        //    "Tried to deallocate a non-existing pointer. Quitting...\n");
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

    // debugf_debug("Region %llx destroyed\n", to_dealloc->base);

    size_t vmo_size_aligned = ROUND_UP(sizeof(virtmem_object_t), PFRAME_SIZE);
    pmm_free(to_dealloc, vmo_size_aligned / PFRAME_SIZE);
}
