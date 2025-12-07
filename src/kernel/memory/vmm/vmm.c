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

atomic_flag VMM_LOCK = ATOMIC_FLAG_INIT;

vmc_t *current_vmc = NULL;
vmc_t *global_vmc  = NULL;
vmc_t *kernel_vmc  = NULL; // for kmalloc()

vmc_t *get_current_vmc() {
    return current_vmc;
}

void vmc_switch(vmc_t *new) {
    spinlock_acquire(&VMM_LOCK);

    current_vmc = new;

    spinlock_release(&VMM_LOCK);
}

void set_kernel_vmc(vmc_t *kvmc) {
    spinlock_acquire(&VMM_LOCK);
    // so that it only gets set once
    if (!kernel_vmc) {
        kernel_vmc = kvmc;
    }
    spinlock_release(&VMM_LOCK);
}

vmc_t *get_kernel_vmc() {
    return kernel_vmc;
}

void set_global_vmc(vmc_t *glob) {
    spinlock_acquire(&VMM_LOCK);
    global_vmc = glob;
    spinlock_release(&VMM_LOCK);
}

vmc_t *get_global_vmc() {
    return global_vmc;
}

// imagine making a function to print stuff that you're going to barely use LMAO
void vmo_dump(vmo_t *vmo) {
    /*debugf_debug("VMO %p\n", vmo);
    debugf_debug("\tprev: %p\n", vmo->prev);
    debugf_debug("\tbase: %llx\n", vmo->base);
    debugf_debug("\tlen %zu\n", vmo->len);
    debugf_debug("\tflags: %llb\n", vmo->flags);
    debugf_debug("\tnext: %p\n", vmo->next);*/
}

static vmm_node_t *vmolist_root_node = NULL;
static vmm_node_t *vmclist_root_node = NULL;

// allocate a physical page
vmm_node_t *vlist_node_alloc(size_t item_size) {
    size_t itemsize_aligned = ROUND_UP(item_size, PFRAME_SIZE);

    vmm_node_t *v = (vmm_node_t *)PHYS_TO_VIRTUAL(
        pmm_alloc_pages(itemsize_aligned / PFRAME_SIZE));

    v->len = itemsize_aligned;

    return v;
}

// we don't waste a whole page for a single VMO/VMC structure
void *vmmlist_alloc(vmm_node_t **root_node, size_t item_size) {
    void *item = NULL;

    if (!(*root_node)) {
        (*root_node) = (vmm_node_t *)vlist_node_alloc(item_size);
    }

    vmm_node_t *v_cur;
    vmm_node_t *v_prev = NULL;

    // find a large enough block for a VMO
    for (v_cur = (*root_node); v_cur->next != NULL; v_cur = v_cur->next) {
        if (v_cur->len >= item_size) {
            break;
        }

        if (!v_cur->next) {
            v_cur->next = vlist_node_alloc(item_size);
        }

        v_prev = v_cur; // 200 iq move
    }

    item        = v_cur;
    v_cur->len -= item_size;

    if (v_cur != (*root_node)) {
        // shift the node
        v_prev->next += item_size;
        memcpy(v_prev->next, v_cur, sizeof(vmm_node_t));
        v_cur = v_prev->next;
    } else {
        // just shift the root node
        (*root_node) = (void *)(*root_node) + item_size;
        memcpy((*root_node), v_cur, sizeof(vmm_node_t));
    }

    return item;
}

void vmmlist_free(vmm_node_t **root_node, size_t item_size, void *tofree) {
    // cases:
    // it was the first VMO allocated
    // it's somewhere in between two nodes
    //      check if we can merge something
    // it's at the end

    // tbf we can just do a for loop
    vmm_node_t *v_cur    = NULL;
    vmm_node_t *v_prev   = NULL;
    vmm_node_t *v_tofree = tofree;

    if (tofree < (*root_node)) {
        v_cur = (*root_node);

        if (((void *)v_tofree) + item_size == (*root_node)) {
            v_tofree->len  = (*root_node)->len + item_size;
            v_tofree->next = (*root_node)->next;
        } else {
            v_tofree->len  = item_size;
            v_tofree->next = v_cur;
        }

        (*root_node) = v_tofree;
        return;
    }

    for (v_cur = (*root_node); v_cur != NULL; v_cur = v_cur->next) {
        vmm_node_t *v_next = v_cur->next;

        if (v_next < tofree) {
            v_prev = v_cur;
            continue;
        }

        // if tofree sits right after current node
        if ((v_cur + (v_cur->len)) == tofree) {
            v_cur->len += item_size;
        } else if ((v_next - item_size) == tofree) {
            // here, if it sits right before the next node
            vmm_node_t *v_new = (v_next - item_size);
            v_new->len        = v_next->len + item_size;
            v_new->next       = v_next->next;
            v_cur->next       = v_new;
        } else {
            // last case, just put it in the middle of the two xD
            // this might also work at the end of the list (v_next is NULL)
            v_tofree->len  = item_size;
            v_tofree->next = v_next;
            v_cur->next    = v_tofree;
        }

        break; // we don't need to go on with the loop
    }

    if (v_cur->len % PFRAME_SIZE != 0) {
        return;
    }

    // if it's page-aligned (should be 0x1000 most of the time), we can free it
    v_tofree = v_cur;
    if (v_tofree == (*root_node)) {
        (*root_node) = (*root_node)->next;
    } else {
        v_prev->next = v_tofree->next;
    }

    pmm_free(v_tofree, v_tofree->len / PFRAME_SIZE);
}

// useful wrapper functions //

vmc_t *vmc_alloc() {
    return (vmc_t *)vmmlist_alloc(&vmclist_root_node, sizeof(vmc_t));
}

vmo_t *vmo_alloc() {
    return (vmo_t *)vmmlist_alloc(&vmolist_root_node, sizeof(vmo_t));
}

void vmc_free(vmc_t *v) {
    vmmlist_free(&vmclist_root_node, sizeof(vmc_t), v);
}

void vmo_free(vmo_t *v) {
    vmmlist_free(&vmolist_root_node, sizeof(vmo_t), v);
}

// @param length IT'S IN PAGEEEEES
vmo_t *vmo_init(uint64_t base, size_t length, uint64_t flags) {
    vmo_t *vmo = vmo_alloc();

    vmo->base  = base;
    vmo->len   = length;
    vmo->flags = flags;

    vmo->next = NULL;

    return vmo;
}

// @note We will not care if `pml4` is 0x0 :^)
// @param pml4_virt VIRTUAL address
vmc_t *vmc_init(uint64_t *pml4_virt, uint64_t flags) {
    spinlock_acquire(&VMM_LOCK);

    vmc_t *ctx = vmc_alloc();

    if (pml4_virt == NULL) {
        pml4_virt = (uint64_t *)PHYS_TO_VIRTUAL(pmm_alloc_page());
    }

    ctx->pml4_table = (uint64_t *)VIRT_TO_PHYSICAL(pml4_virt);
    ctx->root_vmo   = vmo_init(0x1000, 1, flags);

    spinlock_release(&VMM_LOCK);

    return ctx;
}

void vmc_destroy(vmc_t *ctx) {

    spinlock_acquire(&VMM_LOCK);

    if (VIRT_TO_PHYSICAL(ctx->pml4_table) == (uint64_t)cpu_get_cr(3)) {
        kprintf_warn("Attempted to destroy a pagemap that's currently in use. "
                     "Skipping\n");
        return;
    }

    // Free all VMOs and their associated physical memory
    for (vmo_t *v = ctx->root_vmo; v != NULL;) {
        vmo_t *next = v->next;

        // Only free physical memory if the VMO is mapped
        if (v->flags & VMO_PRESENT) {
            uint64_t phys = pg_virtual_to_phys(ctx->pml4_table, v->base);
            if (phys) {
                pmm_free((void *)PHYS_TO_VIRTUAL(phys), v->len);
            }
        }

        // Free the VMO structure itself
        vmo_free(v);
        v = next;
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
    vmc_free(ctx);

    ctx->pml4_table = NULL;

    spinlock_release(&VMM_LOCK);
}

// @param where after how many pages should we split the VMO
vmo_t *split_vmo_at(vmo_t *src_vmo, size_t where) {
    vmo_t *new_vmo;

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

    // TODO: copy only the higher half (which means also fixing lots of stuff)
    for (int i = 255; i < 512; i++) {
        // debugf("Copying %p[%d](%llx) to %p[%d]\n", k_pml4, i, k_pml4[i],
        //        non_kernel_pml4, i);

        ((uint64_t *)PHYS_TO_VIRTUAL(non_kernel_pml4))[i] = k_pml4[i];
    }
}

// Assumes the CTX has been initialized with vmc_init()
void vmm_init(vmc_t *ctx) {
    for (vmo_t *i = ctx->root_vmo; i != NULL; i = i->next) {
        // every VMO will have the same flags as the root one
        i->flags = ctx->root_vmo->flags;

        // mapping will be done on vma_alloc
    }

    pagemap_copy_to(ctx->pml4_table);
}

// to be used by scheduler
void process_vmm_init(vmc_t **proc_vmcr, uint64_t flags) {
    spinlock_acquire(&VMM_LOCK);

    if (!proc_vmcr) {
        return;
    }

    if (!(*proc_vmcr)) {
        *proc_vmcr = vmc_init(NULL, flags);
    }

    vmc_t *proc_vmc = *proc_vmcr;
    if (proc_vmc->root_vmo) {
        vmo_free(proc_vmc->root_vmo);
    }

    vmo_t **proc_vmor = &proc_vmc->root_vmo;

    for (vmo_t *v = global_vmc->root_vmo; v != NULL; v = v->next) {
        *proc_vmor = vmo_alloc();
        memcpy(*proc_vmor, v, sizeof(vmo_t));

        proc_vmor = &(*proc_vmor)->next;
    }

    proc_vmc->pml4_table = (uint64_t *)pmm_alloc_page();
    memcpy((void *)PHYS_TO_VIRTUAL(proc_vmc->pml4_table),
           global_vmc->pml4_table, PFRAME_SIZE);

    spinlock_release(&VMM_LOCK);
}

void *valloc(vmc_t *ctx, size_t pages, uint8_t flags, void *phys) {
    spinlock_acquire(&VMM_LOCK);

    void *ptr = NULL;

    vmo_t *cur_vmo = ctx->root_vmo;
    vmo_t *new_vmo;

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
    map_region((uint64_t *)PHYS_TO_VIRTUAL(ctx->pml4_table),
               (uint64_t)phys_to_map, (uint64_t)ptr, (uint64_t)pages,
               vmo_to_page_flags(flags));

    // debugf_debug("Returning pointer %p\n", ptr);

    spinlock_release(&VMM_LOCK);

    return (ptr + offset);
}

// @param free do you want to give back the physical address of `ptr` back to
// the PMM? (this will zero out that region on next allocation)
void vfree(vmc_t *ctx, void *ptr, bool free) {
    spinlock_acquire(&VMM_LOCK);

#ifdef CONFIG_VMM_DEBUG
    debugf_debug("Deallocating pointer %p\n", ptr);
#endif

    ptr = (void *)ROUND_DOWN((uint64_t)ptr, PFRAME_SIZE);

    vmo_t *cur_vmo = ctx->root_vmo;
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
                 cur_vmo->len);

    vmo_t *to_dealloc = cur_vmo;
    // d_ is deallocated_
    vmo_t *d_next     = to_dealloc->next;
    vmo_t *d_prev     = NULL;

    if (cur_vmo == ctx->root_vmo) {
        ctx->root_vmo = ctx->root_vmo->next;
    } else {
        for (d_prev = ctx->root_vmo; d_prev->next != to_dealloc;
             d_prev = d_prev->next)
            ;

        d_prev->next = d_next;
    }

    // debugf_debug("Region %llx destroyed\n", to_dealloc->base);
    vmo_free(to_dealloc);

    spinlock_release(&VMM_LOCK);
}

void global_vmc_init(vmc_t *kernel_vmc) {
    if (!kernel_vmc) {
        return;
    }

    if (!global_vmc) {
        global_vmc = vmc_alloc();
    }

    uint64_t *new_pml4 = (uint64_t *)PHYS_TO_VIRTUAL(pmm_alloc_page());
    uint64_t *src_pml4 = (uint64_t *)PHYS_TO_VIRTUAL(kernel_vmc->pml4_table);
    memcpy(new_pml4, src_pml4, PFRAME_SIZE);

    vmo_t **globvmo_cur = &global_vmc->root_vmo;

    for (vmo_t *v = kernel_vmc->root_vmo; v != NULL; v = v->next) {
        *globvmo_cur = vmo_alloc();
        memcpy(*globvmo_cur, v, sizeof(vmo_t));

        globvmo_cur = &(*globvmo_cur)->next;
    }

    global_vmc->pml4_table = new_pml4;

    set_global_vmc(global_vmc);
}
