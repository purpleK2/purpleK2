#include "mmap.h"

#include <memory/vmm/vmm.h>
#include <memory/vmm/vflags.h>
#include <memory/pmm/pmm.h>
#include <paging/paging.h>
#include <scheduler/scheduler.h>
#include <fs/vfs/vfs.h>
#include <errors.h>

#include <string.h>

static uint8_t prot_to_vmo_flags(int prot) {
    uint8_t flags = VMO_USER;

    if (prot & PROT_WRITE) {
        flags |= VMO_RW;
    }

    if (!(prot & PROT_EXEC)) {
        flags |= VMO_NX;
    }

    return flags;
}

static inline size_t page_align_up(size_t val) {
    return (val + MMAP_PAGE_SIZE - 1) & ~(MMAP_PAGE_SIZE - 1);
}

static inline size_t page_align_down(size_t val) {
    return val & ~(MMAP_PAGE_SIZE - 1);
}

static void *find_free_region(vmc_t *vmc, size_t pages) {
    uint64_t candidate = MMAP_REGION_START;
    size_t needed_bytes = pages * MMAP_PAGE_SIZE;

    for (vmo_t *v = vmc->root_vmo; v != NULL; v = v->next) {
        uint64_t vmo_start = v->base;
        uint64_t vmo_end   = v->base + v->len * MMAP_PAGE_SIZE;

        if (vmo_end <= candidate) {
            continue;
        }

        if ((v->flags & VMO_ALLOCATED) && vmo_start < candidate + needed_bytes) {
            candidate = vmo_end;
            if (candidate >= MMAP_REGION_END) {
                return NULL;
            }
            continue;
        }

        if (!(v->flags & VMO_ALLOCATED)) {
            continue;
        }

        if (vmo_start >= candidate + needed_bytes) {
            break;
        }

        candidate = vmo_end;
    }

    if (candidate + needed_bytes > MMAP_REGION_END) {
        return NULL;
    }

    return (void *)candidate;
}

static bool region_is_free(vmc_t *vmc, uint64_t base, size_t pages) {
    uint64_t end = base + pages * MMAP_PAGE_SIZE;

    for (vmo_t *v = vmc->root_vmo; v != NULL; v = v->next) {
        if (!(v->flags & VMO_ALLOCATED)) {
            continue;
        }

        uint64_t vmo_start = v->base;
        uint64_t vmo_end   = v->base + v->len * MMAP_PAGE_SIZE;

        if (!(end <= vmo_start || base >= vmo_end)) {
            return false;
        }
    }

    return true;
}

void *do_mmap(vmc_t *vmc, void *addr, size_t length, int prot,
              int flags, vnode_t *vnode, size_t offset) {

    if (!vmc) {
        return MAP_FAILED;
    }

    if (length == 0) {
        return MAP_FAILED;
    }

    if (!(flags & (MAP_PRIVATE | MAP_SHARED))) {
        return MAP_FAILED;
    }

    if ((flags & MAP_PRIVATE) && (flags & MAP_SHARED)) {
        return MAP_FAILED;
    }

    if (!(flags & MAP_ANONYMOUS)) {
        if (!vnode) {
            return MAP_FAILED;
        }
    }

    size_t aligned_length = page_align_up(length);
    size_t pages = aligned_length / MMAP_PAGE_SIZE;

    uint8_t vmo_flags = prot_to_vmo_flags(prot);

    void *map_addr = NULL;

    if (flags & MAP_FIXED) {
        uint64_t base = (uint64_t)(uintptr_t)addr;

        if (base & (MMAP_PAGE_SIZE - 1)) {
            return MAP_FAILED;
        }

        if (base < MMAP_REGION_START || base + aligned_length > MMAP_REGION_END) {
            if (base == 0) {
                return MAP_FAILED;
            }
        }

        if (!region_is_free(vmc, base, pages)) {
            do_munmap(vmc, (void *)base, aligned_length);
        }

        map_addr = valloc_at(vmc, (void *)base, pages, vmo_flags, NULL);
    } else if (addr != NULL) {
        uint64_t base = page_align_down((uint64_t)(uintptr_t)addr);

        if (base >= MMAP_REGION_START && base + aligned_length <= MMAP_REGION_END
            && region_is_free(vmc, base, pages)) {
            map_addr = valloc_at(vmc, (void *)base, pages, vmo_flags, NULL);
        }

        if (!map_addr) {
            void *free_addr = find_free_region(vmc, pages);
            if (!free_addr) {
                return MAP_FAILED;
            }
            map_addr = valloc_at(vmc, free_addr, pages, vmo_flags, NULL);
        }
    } else {
        void *free_addr = find_free_region(vmc, pages);
        if (!free_addr) {
            return MAP_FAILED;
        }
        map_addr = valloc_at(vmc, free_addr, pages, vmo_flags, NULL);
    }

    if (!map_addr) {
        return MAP_FAILED;
    }

    uint64_t *pml4 = (uint64_t *)PHYS_TO_VIRTUAL(vmc->pml4_table);

    if (flags & MAP_ANONYMOUS) {
        for (size_t i = 0; i < pages; i++) {
            uint64_t virt = (uint64_t)(uintptr_t)map_addr + i * MMAP_PAGE_SIZE;
            uint64_t phys = pg_virtual_to_phys(pml4, virt);
            if (phys) {
                void *page_virt = (void *)PHYS_TO_VIRTUAL(phys);
                memset(page_virt, 0, MMAP_PAGE_SIZE);
            }
        }
    } else {
        for (size_t i = 0; i < pages; i++) {
            uint64_t virt = (uint64_t)(uintptr_t)map_addr + i * MMAP_PAGE_SIZE;
            uint64_t phys = pg_virtual_to_phys(pml4, virt);
            if (!phys) {
                continue;
            }

            void *page_virt = (void *)PHYS_TO_VIRTUAL(phys);
            memset(page_virt, 0, MMAP_PAGE_SIZE);

            size_t file_off = offset + i * MMAP_PAGE_SIZE;
            size_t to_read = MMAP_PAGE_SIZE;

            int ret = vfs_read(vnode, to_read, file_off, page_virt);
            (void)ret;
        }
    }

    return map_addr;
}

int do_munmap(vmc_t *vmc, void *addr, size_t length) {
    if (!vmc || !addr) {
        return -1;
    }

    if (length == 0) {
        return -1;
    }

    uint64_t base = (uint64_t)(uintptr_t)addr;

    if (base & (MMAP_PAGE_SIZE - 1)) {
        return -1;
    }

    size_t aligned_length = page_align_up(length);
    (void)aligned_length;

    vfree(vmc, addr, true);

    return 0;
}

int do_mprotect(vmc_t *vmc, void *addr, size_t length, int prot) {
    if (!vmc || !addr) {
        return -1;
    }

    if (length == 0) {
        return -1;
    }

    uint64_t base = (uint64_t)(uintptr_t)addr;

    if (base & (MMAP_PAGE_SIZE - 1)) {
        return -1;
    }

    size_t aligned_length = page_align_up(length);
    size_t pages = aligned_length / MMAP_PAGE_SIZE;

    uint64_t page_flags = PMLE_PRESENT | PMLE_USER;

    if (prot & PROT_WRITE) {
        page_flags |= PMLE_WRITE;
    }

    if (!(prot & PROT_EXEC)) {
        page_flags |= PMLE_NOT_EXECUTABLE;
    }

    uint64_t *pml4 = (uint64_t *)PHYS_TO_VIRTUAL(vmc->pml4_table);

    for (size_t i = 0; i < pages; i++) {
        uint64_t virt = base + i * MMAP_PAGE_SIZE;
        uint64_t phys = pg_virtual_to_phys(pml4, virt);

        if (phys) {
            unmap_page(pml4, virt);
            map_phys_to_page(pml4, phys, virt, page_flags);
            _invalidate(virt);
        }
    }

    return 0;
}
