#include "loader/module/module_loader.h"
#include "elf/elf.h"
#include "elf/sym.h"
#include "fs/file_io.h"
#include "fs/vfs/vfs.h"
#include "kernel.h"
#include "memory/pmm/pmm.h"
#include "memory/vmm/vflags.h"
#include "memory/vmm/vmm.h"
#include "module/modinfo.h"
#include "paging/paging.h"
#include "stdio.h"

#include <memory/heap/kheap.h>
#include <module/mod.h>
#include <stdint.h>
#include <string.h>

#define ALIGN_UP(addr, align)                                                  \
    ((((uint64_t)(addr)) + ((align) - 1)) & ~((align) - 1))

static uintptr_t next_module_base = 0;

static uintptr_t elf_getSymbolAddress(Elf64_Ehdr *ehdr, int table,
                                      uintptr_t idx) {
    if (table == SHN_UNDEF || idx == SHN_UNDEF)
        return (uintptr_t)-1;

    Elf64_Shdr *symtab    = ELF_SECTION(ehdr, table);
    uintptr_t entry_count = symtab->sh_size / symtab->sh_entsize;

    if (idx >= entry_count) {
        debugf_warn("Symbol index out of range (%d:%lu)\n", table, idx);
        return (uintptr_t)-1;
    }

    uintptr_t symaddr = (uintptr_t)ehdr + symtab->sh_offset;
    Elf64_Sym *symbol = &((Elf64_Sym *)symaddr)[idx];

    switch (symbol->st_shndx) {
    case SHN_UNDEF: {
        Elf64_Shdr *strtab = ELF_SECTION(ehdr, symtab->sh_link);
        char *name         = (char *)ehdr + strtab->sh_offset + symbol->st_name;

        uintptr_t addr =
            resolve_symbol_addr((get_bootloader_data()->kernel_file_data),
                                get_bootloader_data()->kernel_file_size, name);
        if (addr == (uintptr_t)NULL) {
            if (ELF64_ST_BIND(symbol->st_info) & STB_WEAK) {
                debugf_warn("Weak symbol '%s' not found - initialized as 0\n",
                            name);
                return 0;
            } else {
                debugf_warn("External symbol '%s' not found in kernel.\n",
                            name);
                return (uintptr_t)-1;
            }
        }
        return addr;
    }
    case SHN_ABS:
        return symbol->st_value;

    default: {
        Elf64_Shdr *target = ELF_SECTION(ehdr, symbol->st_shndx);
        return (uintptr_t)target->sh_addr + symbol->st_value;
    }
    }
}

static uintptr_t elf_relocateSymbol(Elf64_Ehdr *ehdr, Elf64_Rel *rel,
                                    Elf64_Shdr *reltab) {
    Elf64_Shdr *shdr     = ELF_SECTION(ehdr, reltab->sh_info);
    uintptr_t *reference = (uintptr_t *)(shdr->sh_addr + rel->r_offset);

    uintptr_t symval = 0x0;
    if (ELF64_R_SYM(rel->r_info) != SHN_UNDEF) {
        symval = elf_getSymbolAddress(ehdr, reltab->sh_link,
                                      ELF64_R_SYM(rel->r_info));
        if (symval == (uintptr_t)-1)
            return (uintptr_t)-1;
    }

    switch (ELF64_R_TYPE(rel->r_info)) {
    case R_X86_64_NONE:
        break;
    case R_X86_64_64:
        *((uint64_t *)reference) = RELOCATE_X86_64_3264(symval, *reference);
        break;
    case R_X86_64_32:
        *((uint32_t *)reference) = RELOCATE_X86_64_3264(symval, *reference);
        break;
    case R_X86_64_PLT32:
        debugf_warn("Cannot parse PLT32! Link with -nostdlib and compile with "
                    "-fno-pie!\n");
        return (uintptr_t)-1;
    case R_X86_64_PC32:
        *((uint32_t *)reference) =
            RELOCATE_X86_64_PC32(symval, *reference, (uintptr_t)reference);
        break;
    default:
        debugf_warn("Unsupported relocation type: %lu\n",
                    ELF64_R_TYPE(rel->r_info));
        return (uintptr_t)-1;
    }
    return symval;
}

static uintptr_t elf_relocateSymbolAddend(Elf64_Ehdr *ehdr, Elf64_Rela *rel,
                                          Elf64_Shdr *reltab) {
    Elf64_Shdr *target_section = ELF_SECTION(ehdr, reltab->sh_info);
    uint64_t *reference = (uint64_t *)(target_section->sh_addr + rel->r_offset);

    uintptr_t symval = 0x0;
    if (ELF64_R_SYM(rel->r_info) != SHN_UNDEF) {
        symval = elf_getSymbolAddress(ehdr, reltab->sh_link,
                                      ELF64_R_SYM(rel->r_info));
        if (symval == (uintptr_t)-1)
            return (uintptr_t)-1;
    }

    switch (ELF64_R_TYPE(rel->r_info)) {
    case R_X86_64_NONE:
        break;
    case R_X86_64_64: {
        uint64_t r64 = RELOCATE_X86_64_3264(symval, (int)rel->r_addend);
        memcpy(reference, &r64, sizeof(uint64_t));
        break;
    }
    case R_X86_64_32: {
        uint32_t r32 =
            (uint32_t)RELOCATE_X86_64_3264(symval, (int)rel->r_addend);
        memcpy(reference, &r32, sizeof(uint32_t));
        break;
    }
    case R_X86_64_32S:
        *((int32_t *)reference) =
            (int32_t)RELOCATE_X86_64_3264(symval, *reference);
        break;
    case R_X86_64_PLT32:
        debugf_warn("Cannot parse PLT32! Link with -nostdlib and compile with "
                    "-fno-pie!\n");
        return (uintptr_t)-1;
    case R_X86_64_PC32: {
        uint32_t pc32 = RELOCATE_X86_64_PC32(symval, (int)rel->r_addend,
                                             (uintptr_t)reference);
        memcpy(reference, &pc32, sizeof(uint32_t));
        break;
    }
    default:
        debugf_warn("Unsupported relocation type: %lu\n",
                    ELF64_R_TYPE(rel->r_info));
        return (uintptr_t)-1;
    }
    return symval;
}

uintptr_t elf_findSymbol(Elf64_Ehdr *ehdr, char *name) {
    if (!ehdr || !name)
        return (uintptr_t)NULL;

    for (unsigned int i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr *shdr = ELF_SECTION(ehdr, i);
        if (shdr->sh_type != SHT_SYMTAB)
            continue;

        Elf64_Shdr *strtab = ELF_SECTION(ehdr, shdr->sh_link);
        if (!strtab) {
            debugf_warn("String table not found\n");
            return (uintptr_t)NULL;
        }

        Elf64_Sym *symtable = (Elf64_Sym *)((uintptr_t)ehdr + shdr->sh_offset);
        for (unsigned int sym = 0; sym < shdr->sh_size / shdr->sh_entsize;
             sym++) {
            Elf64_Sym *symbol = &symtable[sym];
            char *symname = (char *)ehdr + strtab->sh_offset + symbol->st_name;

            if (!strcmp(name, symname)) {
                return elf_getSymbolAddress(ehdr, i, sym);
            }
        }
    }
    return (uintptr_t)NULL;
}

extern uint64_t __kernel_start, __kernel_end;

static int validate_elf_header(Elf64_Ehdr *ehdr) {
    // Check ELF magic number
    if (memcmp(ehdr->e_ident,
               "\x7F"
               "E"
               "L"
               "F",
               4) != 0) {
        debugf_warn("Invalid ELF magic number\n");
        return 0;
    }

    // Check for 64-bit ELF
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        debugf_warn("Not a 64-bit ELF file\n");
        return 0;
    }

    // Check for x86_64 architecture
    if (ehdr->e_machine != EM_X86_64) {
        debugf_warn("Not an x86_64 ELF file\n");
        return 0;
    }

    // Check for relocatable object file
    if (ehdr->e_type != ET_REL) {
        debugf_warn("Not a relocatable ELF file\n");
        return 0;
    }

    return 1;
}

static void cleanup_module_allocation(uintptr_t start_addr,
                                      uintptr_t current_addr) {
    // Free allocated pages if loading fails
    if (start_addr && current_addr > start_addr) {
        size_t total_pages = (current_addr - start_addr) / PAGE_SIZE;
        for (size_t i = 0; i < total_pages; i++) {
            uint64_t virt_addr = start_addr + (i * PAGE_SIZE);
            // Get physical address from page table and free it
            // This would need to be implemented based on your paging system
            unmap_page(
                (uint64_t *)(uintptr_t)PHYS_TO_VIRTUAL(get_kernel_pml4()),
                virt_addr);
        }
    }
}

mod_t *load_module(const char *file_path) {
    if (!file_path) {
        debugf_warn("Invalid file path\n");
        return NULL;
    }

    struct file_io *file = open(file_path, 0);
    if (!file) {
        debugf_warn("Failed to open module file: %s\n", file_path);
        return NULL;
    }

    if (file->size < sizeof(Elf64_Ehdr)) {
        debugf_warn("File too small to be a valid ELF\n");
        close(file);
        return NULL;
    }

    // Initialize module base address if first module
    if (next_module_base == 0) {
        uint64_t kernel_end = (uint64_t)(uintptr_t)&__kernel_end;

        next_module_base = ALIGN_UP((kernel_end), PAGE_SIZE);
        debugf_debug("Base of the first module is 0x%016llx\n",
                     next_module_base);
        if (next_module_base == 0) {
            close(file);
            return NULL;
        }
    }

    void *buffer = kmalloc(file->size);
    if (!buffer) {
        debugf_warn("Failed to allocate buffer for module\n");
        close(file);
        return NULL;
    }

    size_t read_from_file = read(file, file->size, buffer);
    if (read_from_file != file->size) {
        debugf_warn("Failed to read complete module file! Needed size: %d, "
                    "read_size: %d",
                    file->size, read_from_file);
        kfree(buffer);
        close(file);
        return NULL;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)buffer;

    // Validate ELF header
    if (!validate_elf_header(ehdr)) {
        kfree(buffer);
        close(file);
        return NULL;
    }

    Elf64_Shdr *shdr          = ELF_SHDR(ehdr);
    uint64_t this_mod_start   = next_module_base;
    uint64_t mod_addr_counter = this_mod_start;

    uint64_t total_size = 0;
    for (unsigned int i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr *section = &shdr[i];
        if ((section->sh_flags & SHF_ALLOC) && section->sh_size) {
            total_size +=
                ALIGN_UP(section->sh_size, section->sh_addralign ?: 1);
        }
    }

    if (total_size == 0) {
        debugf_warn("No allocatable sections found\n");
        kfree(buffer);
        close(file);
        return NULL;
    }

    debugf_debug("Loading module %s, total size needed: 0x%llx bytes\n",
                 file_path, total_size);

    // Second pass: allocate and map sections
    for (unsigned int i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr *section = &shdr[i];
        if ((section->sh_flags & SHF_ALLOC) && section->sh_size) {
            // Align address according to section requirements
            size_t align     = section->sh_addralign ?: 1;
            mod_addr_counter = ALIGN_UP(mod_addr_counter, align);

            // Calculate number of pages needed for this section
            size_t page_count =
                ALIGN_UP(section->sh_size, PAGE_SIZE) / PAGE_SIZE;
            void *addr_phys = pmm_alloc_contiguous_pages(page_count);

            if (!addr_phys) {
                debugf_warn(
                    "Failed to allocate physical pages for section %u\n", i);
                cleanup_module_allocation(this_mod_start, mod_addr_counter);
                kfree(buffer);
                close(file);
                return NULL;
            }

            map_region_to_page(
                (uint64_t *)(uintptr_t)PHYS_TO_VIRTUAL(get_kernel_pml4()),
                (uint64_t)(uintptr_t)addr_phys, mod_addr_counter, page_count,
                0b111);

            // Set section address and copy data
            section->sh_addr = mod_addr_counter;

            memset((void *)(uintptr_t)mod_addr_counter, 0,
                   page_count * PAGE_SIZE);

            if (section->sh_type != SHT_NOBITS) {
                memcpy((void *)(uintptr_t)mod_addr_counter,
                       (void *)((uintptr_t)ehdr + section->sh_offset),
                       section->sh_size);
            }

            _invalidate(mod_addr_counter);
            debugf_debug("Mapped 0x%.16llx-0x%.16llx -> 0x%.16llx-0x%.16llx\n",
                         (uint64_t)(uintptr_t)addr_phys,
                         (uint64_t)(uintptr_t)addr_phys + page_count * 0x1000,
                         mod_addr_counter,
                         mod_addr_counter + page_count * 0x1000);

            mod_addr_counter += page_count * PAGE_SIZE;
        } else {
            section->sh_addr = (uintptr_t)ehdr + section->sh_offset;
        }
    }

    // Perform relocations
    for (unsigned int i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr *section = &shdr[i];
        if (section->sh_type == SHT_REL) {
            debugf_debug("Processing REL section %u with %llu relocations\n", i,
                         section->sh_size / section->sh_entsize);
            for (unsigned int idx = 0;
                 idx < section->sh_size / section->sh_entsize; idx++) {
                Elf64_Rel *rel =
                    &((Elf64_Rel *)((uintptr_t)ehdr + section->sh_offset))[idx];
                if (elf_relocateSymbol(ehdr, rel, section) == (uintptr_t)-1) {
                    debugf_warn("Relocation failed in section %u, entry %u\n",
                                i, idx);
                    cleanup_module_allocation(this_mod_start, mod_addr_counter);
                    kfree(buffer);
                    close(file);
                    return NULL;
                }
            }
        } else if (section->sh_type == SHT_RELA) {
            debugf_debug("Processing RELA section %u with %llu relocations\n",
                         i, section->sh_size / section->sh_entsize);
            for (unsigned int idx = 0;
                 idx < section->sh_size / section->sh_entsize; idx++) {
                Elf64_Rela *rela = &(
                    (Elf64_Rela *)((uintptr_t)ehdr + section->sh_offset))[idx];
                if (elf_relocateSymbolAddend(ehdr, rela, section) ==
                    (uintptr_t)-1) {
                    debugf_warn("Relocation with addend failed in section %u, "
                                "entry %u\n",
                                i, idx);
                    cleanup_module_allocation(this_mod_start, mod_addr_counter);
                    kfree(buffer);
                    close(file);
                    return NULL;
                }
            }
        }
    }

    // Find entry and exit points
    uintptr_t entry_point = elf_findSymbol(ehdr, "module_entry");
    if (!entry_point) {
        debugf_warn("No entry point 'module_entry' found in module\n");
        cleanup_module_allocation(this_mod_start, mod_addr_counter);
        kfree(buffer);
        close(file);
        return NULL;
    }

    uintptr_t exit_point = elf_findSymbol(ehdr, "module_exit");
    if (!exit_point) {
        debugf_warn("Warning: No exit point 'module_exit' found in module\n");
    }

    uintptr_t mod_info = elf_findSymbol(ehdr, "modinfo");
    if (!mod_info) {
        debugf_warn("No module info found!");
        cleanup_module_allocation(this_mod_start, mod_addr_counter);
        kfree(buffer);
        close(file);
        return NULL;
    }

    // Create module structure
    mod_t *mod = kmalloc(sizeof(mod_t));
    if (!mod) {
        debugf_warn("Failed to allocate module structure\n");
        cleanup_module_allocation(this_mod_start, mod_addr_counter);
        kfree(buffer);
        close(file);
        return NULL;
    }

    mod->base_address = (void *)(uintptr_t)this_mod_start;
    mod->entry_point  = (void (*)(void))entry_point;
    mod->exit_point   = (void (*)(void))exit_point;
    mod->modinfo      = (modinfo_t *)mod_info;

    next_module_base = ALIGN_UP(mod_addr_counter, PAGE_SIZE);

    debugf_debug(
        "Module %s (name: %s) loaded successfully: base=0x%llx, entry=0x%llx, "
        "exit=0x%llx\n",
        file_path, mod->modinfo->name, (uint64_t)(uintptr_t)mod->base_address,
        (uint64_t)(uintptr_t)mod->entry_point,
        (uint64_t)(uintptr_t)mod->exit_point);

    debugf("Name: %s\nVersion: %s\nAuthor: %s\nLicense: %s\nDescription: "
           "\n\t%s\nURL: %s\nPriority: %i\n",
           mod->modinfo->name, mod->modinfo->version, mod->modinfo->author,
           mod->modinfo->license, mod->modinfo->description, mod->modinfo->url,
           mod->modinfo->priority);

    debugf("Dependencies: \n");

    int i = 0;
    while (mod->modinfo->deps[i] != NULL) {
        debugf("\t - %s\n", mod->modinfo->deps[i]);
        i++;
    }

    // Clean up temporary allocations
    vfree(get_current_ctx(), buffer, true);
    close(file);

    return mod;
}