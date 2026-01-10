#include "elfloader.h"
#include "util/macro.h"

#include <autoconf.h>
#include <errors.h>
#include <kernel.h>
#include <stdio.h>
#include <string.h>

#include <fs/file_io.h>
#include <memory/heap/kheap.h>
#include <memory/pmm/pmm.h>
#include <memory/vmm/vflags.h>
#include <memory/vmm/vmm.h>
#include <paging/paging.h>
#include <scheduler/scheduler.h>

#include <util/assert.h>

int elf_validate(const Elf64_Ehdr *eh) {
    if (eh->e_ident[EI_MAG0] != ELFMAG0) return -1;
    if (eh->e_ident[EI_MAG1] != ELFMAG1) return -1;
    if (eh->e_ident[EI_MAG2] != ELFMAG2) return -1;
    if (eh->e_ident[EI_MAG3] != ELFMAG3) return -1;
    if (eh->e_ident[EI_CLASS] != ELFCLASS64) return -1;
    if (eh->e_ident[EI_DATA] != ELFDATA2LSB) return -1;
    if (eh->e_machine != EM_X86_64) return -1;
    if (eh->e_type != ET_EXEC && eh->e_type != ET_DYN) return -1;
    if (eh->e_phentsize != sizeof(Elf64_Phdr)) return -1;
    return 0;
}

static uint64_t elf_pf_to_page_flags(uint32_t pf_flags) {
    uint64_t flags = PMLE_PRESENT | PMLE_USER;
    
    if (pf_flags & PF_W) {
        flags |= PMLE_WRITE;
    }
    
    if (!(pf_flags & PF_X)) {
        flags |= PMLE_NOT_EXECUTABLE;
    }

    if ((pf_flags & PF_W) && (pf_flags & PF_X)) {
        debugf_warn("Warning W+X segment detected!\n");
    }
    
    return flags;
}

int load_elf(const char *path, elf_program_t *out) {
    asm volatile("cli");
    if (!path || !out) {
        return -ENULLPTR;
    }

    debugf_debug("Loading ELF binary from %s\n", path);

    fileio_t *elf_file = open(path, 0);
    if (!elf_file || (int64_t)elf_file < 0) {
        debugf_warn("Failed to open ELF file %s: %d\n", path, (int64_t)elf_file);
        return -ENOENT;
    }

    Elf64_Ehdr eh;
    if (read(elf_file, sizeof(Elf64_Ehdr), (char *)&eh) != sizeof(Elf64_Ehdr)) {
        debugf_warn("Failed to read ELF header from %s\n", path);
        close(elf_file);
        return -EIO;
    }

    if (elf_validate(&eh) != 0) {
        debugf_warn("ELF file %s is not valid\n", path);
        close(elf_file);
        return -EINVAL;
    }

    debugf_debug("ELF: entry=0x%llx phnum=%d\n", eh.e_entry, eh.e_phnum);

    Elf64_Phdr *phdrs = kmalloc(sizeof(Elf64_Phdr) * eh.e_phnum);
    if (!phdrs) {
        close(elf_file);
        return -ENOMEM;
    }

    seek(elf_file, eh.e_phoff, SEEK_SET);
    if (read(elf_file, sizeof(Elf64_Phdr) * eh.e_phnum, (char *)phdrs) !=
        sizeof(Elf64_Phdr) * eh.e_phnum) {
        debugf_warn("Failed to read ELF program headers from %s\n", path);
        kfree(phdrs);
        close(elf_file);
        return -EIO;
    }

    char *proc_name = strdup(path);
    int pid = proc_create((void (*)(void))eh.e_entry, TF_MODE_USER, proc_name);
    if (pid < 0) {
        debugf_warn("Failed to create process for ELF %s\n", path);
        kfree(phdrs);
        close(elf_file);
        return pid;
    }

    pcb_t *proc = pcb_lookup(pid);
    if (!proc || !proc->vmc) {
        debugf_warn("Failed to lookup process PID=%d\n", pid);
        kfree(phdrs);
        close(elf_file);
        return -EINVAL;
    }

    uint64_t *pml4 = (uint64_t *)PHYS_TO_VIRTUAL(proc->vmc->pml4_table);

    for (int i = 0; i < eh.e_phnum; i++) {
        Elf64_Phdr *phdr = &phdrs[i];

        if (phdr->p_type != PT_LOAD) {
            continue;
        }

        debugf_debug("Loading segment %d: vaddr=0x%llx memsz=0x%llx filesz=0x%llx flags=0x%x\n",
                     i, phdr->p_vaddr, phdr->p_memsz, phdr->p_filesz, phdr->p_flags);


        uint64_t seg_page_start = ROUND_DOWN(phdr->p_vaddr, PFRAME_SIZE);
        uint64_t seg_page_end = ROUND_UP(phdr->p_vaddr + phdr->p_memsz, PFRAME_SIZE);
        uint64_t pages = (seg_page_end - seg_page_start) / PFRAME_SIZE;

        uint64_t phys_base = (uint64_t)pmm_alloc_pages(pages);
        if (!phys_base) {
            debugf_warn("Failed to allocate %llu pages for segment %d\n", pages, i);
            kfree(phdrs);
            close(elf_file);
            return -ENOMEM;
        }

        memset((void *)PHYS_TO_VIRTUAL(phys_base), 0, pages * PFRAME_SIZE);

        uint64_t page_flags = elf_pf_to_page_flags(phdr->p_flags);
        map_region(pml4, phys_base, seg_page_start, pages, page_flags);

        if (phdr->p_filesz > 0) {
            seek(elf_file, phdr->p_offset, SEEK_SET);

            uint64_t offset_in_page = phdr->p_vaddr - seg_page_start;
            void *dest = (void *)(PHYS_TO_VIRTUAL(phys_base) + offset_in_page);

            if (read(elf_file, phdr->p_filesz, dest) != phdr->p_filesz) {
                debugf_warn("Failed to read segment %d data\n", i);
                kfree(phdrs);
                close(elf_file);
                return -EIO;
            }

        }

    }

    close(elf_file);
    kfree(phdrs);

    if (!is_mapped(pml4, eh.e_entry)) {
        debugf_warn("Entry point 0x%llx is not mapped!\n", eh.e_entry);
        return -EINVAL;
    }

    if (out) {
        out->pid = pid;
        out->pcb = proc;
        out->main_thread = proc->main_thread;
        out->entry = eh.e_entry;
    }

    debugf_debug("ELF loaded successfully: PID=%d entry=0x%llx", pid, eh.e_entry);

    asm volatile("sti");

    return EOK;
}