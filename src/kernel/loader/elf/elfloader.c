#include "elfloader.h"
#include "util/macro.h"

#include <autoconf.h>
#include <errors.h>
#include <kernel.h>
#include <cpu.h>
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

    uint64_t dynamic_vaddr = 0;
    uint64_t tls_vaddr = 0;
    uint64_t tls_offset = 0;
    uint64_t tls_filesz = 0;
    uint64_t tls_memsz = 0;
    uint64_t tls_align = 8;

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

    uint64_t load_bias = 0;

    if (eh.e_type == ET_DYN) {
        load_bias = choose_et_dyn_base();
        debugf_debug("ET_DYN detected, load bias = 0x%llx\n", load_bias);
    }


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

    for (int i = 0; i < eh.e_phnum; i++) {
        Elf64_Phdr *phdr = &phdrs[i];
        
        if (phdr->p_type == PT_TLS) {
            tls_filesz = phdr->p_filesz;
            tls_memsz = phdr->p_memsz;
            tls_vaddr = phdr->p_vaddr;
            tls_offset = phdr->p_offset;
            tls_align = phdr->p_align > 0 ? phdr->p_align : 8;
            
            debugf_debug("Found PT_TLS: vaddr=0x%llx offset=0x%llx filesz=%llu memsz=%llu align=%llu\n",
                         tls_vaddr, tls_offset, tls_filesz, tls_memsz, tls_align);
            break;
        }
    }

    char *proc_name = strdup(path);
    int pid = proc_create((void (*)(void))eh.e_entry + load_bias, TF_MODE_USER, proc_name);
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

        if (phdr->p_type == PT_DYNAMIC) {
            uint64_t dyn_start = ROUND_DOWN(phdr->p_vaddr + load_bias, PFRAME_SIZE);
            uint64_t dyn_end   = ROUND_UP(phdr->p_vaddr + load_bias + phdr->p_memsz, PFRAME_SIZE);
            uint64_t pages     = (dyn_end - dyn_start) / PFRAME_SIZE;

            uint64_t phys = (uint64_t)(uintptr_t)pmm_alloc_pages(pages);
            map_region(pml4, phys, dyn_start, pages, PMLE_USER | PMLE_PRESENT | PMLE_WRITE);
        
            if (phdr->p_filesz > 0) {
                seek(elf_file, phdr->p_offset, SEEK_SET);
                uint64_t offset_in_page = (phdr->p_vaddr + load_bias) - dyn_start;
                void *dest = (void *)(PHYS_TO_VIRTUAL(phys) + offset_in_page);
        
                if (read(elf_file, phdr->p_filesz, dest) != phdr->p_filesz) {
                    debugf_warn("Failed to read PT_DYNAMIC data\n");
                    kfree(phdrs);
                    close(elf_file);
                    return -EIO;
                }
            }
    
            dynamic_vaddr = PHYS_TO_VIRTUAL(phys) + ((phdr->p_vaddr + load_bias) - dyn_start);
        }

        if (phdr->p_type == PT_TLS) {
            continue;
        }

        if (phdr->p_type != PT_LOAD) {
            continue;
        }

        debugf_debug("Loading segment %d: vaddr=0x%llx memsz=0x%llx filesz=0x%llx flags=0x%x\n",
                     i, phdr->p_vaddr, phdr->p_memsz, phdr->p_filesz, phdr->p_flags);

        uint64_t seg_vaddr = phdr->p_vaddr + load_bias;
        uint64_t seg_page_start = ROUND_DOWN(seg_vaddr, PFRAME_SIZE);
        uint64_t seg_page_end   = ROUND_UP(seg_vaddr + phdr->p_memsz, PFRAME_SIZE);

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

            uint64_t offset_in_page = seg_vaddr - seg_page_start;
            void *dest = (void *)(PHYS_TO_VIRTUAL(phys_base) + offset_in_page);

            if (read(elf_file, phdr->p_filesz, dest) != phdr->p_filesz) {
                debugf_warn("Failed to read segment %d data\n", i);
                kfree(phdrs);
                close(elf_file);
                return -EIO;
            }

        }

    }

    Elf64_Rela *rela      = NULL;
    uint64_t    rela_sz   = 0;
    uint64_t    rela_ent  = sizeof(Elf64_Rela);

    if (dynamic_vaddr) {
        Elf64_Dyn *dyn = (Elf64_Dyn *)dynamic_vaddr;

        for (; dyn->d_tag != DT_NULL; dyn++) {
            switch (dyn->d_tag) {
            case DT_RELA:
                rela = (Elf64_Rela *)(dyn->d_un.d_ptr + load_bias);
                break;
            case DT_RELASZ:
                rela_sz = dyn->d_un.d_val;
                break;
            case DT_RELAENT:
                rela_ent = dyn->d_un.d_val;
                break;
            default:
                break;
            }
        }
    }

    if (rela && rela_sz) {
        size_t count = rela_sz / rela_ent;

        debugf_debug("Applying %llu RELA relocations\n", count);

        for (size_t i = 0; i < count; i++) {
            Elf64_Rela *r = &rela[i];
            uint64_t *reloc_vaddr = (uint64_t *)(r->r_offset + load_bias);
            uint64_t phys_addr = pg_virtual_to_phys(pml4, (uint64_t)(uintptr_t)reloc_vaddr);
            uint64_t *reloc_addr = (uint64_t *)PHYS_TO_VIRTUAL(phys_addr);
            *reloc_addr = load_bias + r->r_addend;

            switch (ELF64_R_TYPE(r->r_info)) {
            case R_X86_64_RELATIVE:
                *reloc_addr = load_bias + r->r_addend;
                break;
            default:
                debugf_warn("Unsupported relocation type %llu at index %llu\n",
                            ELF64_R_TYPE(r->r_info), i);
                kfree(phdrs);
                close(elf_file);
                return -EINVAL;
            }
        }
    }

    if (!is_mapped(pml4, eh.e_entry + load_bias)) {
        debugf_warn("Entry point 0x%llx is not mapped!\n", eh.e_entry + load_bias);
        kfree(phdrs);
        close(elf_file);
        return -EINVAL;
    }
    
    if (tls_memsz > 0) {
        size_t tcb_size = sizeof(user_tls_t);
        size_t total_size = tcb_size + tls_memsz;
        total_size = ROUND_UP(total_size, PFRAME_SIZE);
        
        debugf_debug("Allocating TLS: TCB=%zu + data=%llu = %zu bytes\n",
                 tcb_size, tls_memsz, total_size);
        
        if (find_new_tls_base(proc->main_thread, total_size) != EOK) {
            debugf_warn("Failed to allocate TLS\n");
            kfree(phdrs);
            close(elf_file);
            return -ENOMEM;
        }
        
        user_tls_t *tcb = proc->main_thread->tls_ptr;
        uint64_t    fs_base = (uint64_t)proc->main_thread->tls.base_virt;

        uint64_t tls_data_virt = fs_base - tls_memsz;
        (void)tls_data_virt;

        void *tls_data_kern = (void *)((uint64_t)tcb - tls_memsz);

        if (tls_filesz > 0) {
            seek(elf_file, tls_offset, SEEK_SET);
            if (read(elf_file, tls_filesz, tls_data_kern) != tls_filesz) {
                debugf_warn("Failed to read TLS init data\n");
                kfree(phdrs);
                close(elf_file);
                return -EIO;
            }
            debugf_debug("Copied %llu bytes of TLS init data to %p\n", 
                         tls_filesz, tls_data_kern);
        }

        if (tls_memsz > tls_filesz) {
            memset((void *)((uint64_t)tls_data_kern + tls_filesz), 0,
                   tls_memsz - tls_filesz);
        }

        tcb->self = (user_tls_t *)fs_base;
        
    } else {
        if (find_new_tls_base(proc->main_thread, TLS_MIN_SIZE) != EOK) {
            debugf_warn("Failed to allocate basic TLS\n");
            kfree(phdrs);
            close(elf_file);
            return -ENOMEM;
        }
        
        user_tls_t *tcb = proc->main_thread->tls_ptr;
        uint64_t    fs_base = (uint64_t)proc->main_thread->tls.base_virt;
        tcb->self = (user_tls_t *)fs_base;
    }

    if (proc->main_thread && proc->main_thread->tls.base_virt) {
        _cpu_set_msr(0xC0000100, (uint64_t)proc->main_thread->tls.base_virt);
    }

    close(elf_file);
    kfree(phdrs);

    if (out) {
        out->pid = pid;
        out->pcb = proc;
        out->main_thread = proc->main_thread;
        out->entry = eh.e_entry;
    }

    debugf_debug("ELF loaded successfully: PID=%d entry=0x%llx\n", pid, eh.e_entry);

    proc_engage(proc);

    asm volatile("sti");
    return EOK;
}