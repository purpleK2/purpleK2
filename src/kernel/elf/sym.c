#include "sym.h"
#include "memory/pmm/pmm.h"
#include "paging/paging.h"
#include "stdio.h"
#include <string.h>

const char *resolve_symbol_name(void *elf_data, size_t size, uint64_t addr) {
    UNUSED(size);
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_data;
    if (memcmp(ehdr->e_ident,
               "\x7f"
               "ELF",
               4) != 0 ||
        ehdr->e_ident[4] != 2)
        return 0;

    Elf64_Shdr *shdrs = (Elf64_Shdr *)((uint8_t *)elf_data + ehdr->e_shoff);
    const char *shstrtab =
        (const char *)elf_data + shdrs[ehdr->e_shstrndx].sh_offset;

    Elf64_Shdr *symtab_hdr = 0;
    Elf64_Shdr *strtab_hdr = 0;

    for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
        const char *name = shstrtab + shdrs[i].sh_name;
        if (shdrs[i].sh_type == SHT_SYMTAB &&
            (!symtab_hdr || strcmp(name, ".symtab") == 0))
            symtab_hdr = &shdrs[i];
        else if (shdrs[i].sh_type == SHT_STRTAB && strcmp(name, ".strtab") == 0)
            strtab_hdr = &shdrs[i];
    }

    if (!symtab_hdr || !strtab_hdr)
        return 0;

    Elf64_Sym *symbols =
        (Elf64_Sym *)((uint8_t *)elf_data + symtab_hdr->sh_offset);
    uint64_t num_syms  = symtab_hdr->sh_size / sizeof(Elf64_Sym);
    const char *strtab = (const char *)elf_data + strtab_hdr->sh_offset;

    for (uint64_t i = 0; i < num_syms; i++) {
        Elf64_Sym *sym = &symbols[i];
        if ((sym->st_info & 0x0F) == STT_FUNC && addr >= sym->st_value &&
            addr < sym->st_value + sym->st_size) {
            return strtab + sym->st_name;
        }
    }

    return 0;
}

uint64_t resolve_symbol_addr(void *elf_data, size_t size,
                             const char *symbol_name) {
    UNUSED(size);
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_data;
    if (memcmp(ehdr->e_ident,
               "\x7f"
               "ELF",
               4) != 0 ||
        ehdr->e_ident[EI_CLASS] != ELFCLASS64)
        return 0;

    bool is_exec;
    if (ehdr->e_type == ET_REL) {
        is_exec = false;
    } else if (ehdr->e_type == ET_EXEC || ehdr->e_type == ET_DYN) {
        is_exec = true; // Executable or shared library (linked)
    }

    Elf64_Shdr *shdrs = (Elf64_Shdr *)((uint8_t *)elf_data + ehdr->e_shoff);
    const char *shstrtab =
        (const char *)elf_data + shdrs[ehdr->e_shstrndx].sh_offset;

    Elf64_Shdr *symtab_hdr = NULL;
    Elf64_Shdr *strtab_hdr = NULL;

    // Locate .symtab/.dynsym and .strtab/.dynstr
    for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
        const char *name = shstrtab + shdrs[i].sh_name;
        if ((shdrs[i].sh_type == SHT_SYMTAB ||
             shdrs[i].sh_type == SHT_DYNSYM) &&
            (!symtab_hdr || strcmp(name, ".symtab") == 0 ||
             strcmp(name, ".dynsym") == 0))
            symtab_hdr = &shdrs[i];
        else if (shdrs[i].sh_type == SHT_STRTAB &&
                 (strcmp(name, ".strtab") == 0 || strcmp(name, ".dynstr") == 0))
            strtab_hdr = &shdrs[i];
    }

    if (!symtab_hdr || !strtab_hdr)
        return 0;

    Elf64_Sym *symbols =
        (Elf64_Sym *)((uint8_t *)elf_data + symtab_hdr->sh_offset);
    uint64_t num_syms  = symtab_hdr->sh_size / sizeof(Elf64_Sym);
    const char *strtab = (const char *)elf_data + strtab_hdr->sh_offset;

    for (uint64_t i = 0; i < num_syms; i++) {
        Elf64_Sym *sym = &symbols[i];
        if (sym->st_name == 0)
            continue;

        const char *name = strtab + sym->st_name;
        if (strcmp(name, symbol_name) != 0)
            continue;

        uint8_t bind = ELF64_ST_BIND(sym->st_info);
        if (bind != STB_GLOBAL && bind != STB_WEAK)
            continue;

        if (sym->st_shndx == SHN_UNDEF)
            continue;

        if (is_exec) {
            return sym->st_value;
        } else {
            return sym->st_value + shdrs[sym->st_shndx].sh_addr;
        }
    }

    return 0;
}

uint64_t resolve_module_symbol(Elf64_Ehdr *ehdr, const char *symbol_name,
                               uint8_t *load_base) {
    Elf64_Shdr *shdrs = (Elf64_Shdr *)((uint8_t *)ehdr + ehdr->e_shoff);
    const char *shstrtab =
        (const char *)ehdr + shdrs[ehdr->e_shstrndx].sh_offset;

    Elf64_Shdr *symtab_hdr = NULL;
    Elf64_Shdr *strtab_hdr = NULL;

    for (uint16_t i = 0; i < ehdr->e_shnum; i++) {
        const char *name = shstrtab + shdrs[i].sh_name;
        if (shdrs[i].sh_type == SHT_SYMTAB && !symtab_hdr)
            symtab_hdr = &shdrs[i];
        else if (shdrs[i].sh_type == SHT_STRTAB && strcmp(name, ".strtab") == 0)
            strtab_hdr = &shdrs[i];
    }

    if (!symtab_hdr || !strtab_hdr)
        return 0;

    Elf64_Sym *symbols = (Elf64_Sym *)((uint8_t *)ehdr + symtab_hdr->sh_offset);
    size_t num_syms    = symtab_hdr->sh_size / sizeof(Elf64_Sym);
    const char *strtab = (const char *)ehdr + strtab_hdr->sh_offset;

    for (size_t i = 0; i < num_syms; i++) {
        Elf64_Sym *sym = &symbols[i];
        if (sym->st_name == 0)
            continue;

        const char *name = strtab + sym->st_name;
        if (strcmp(name, symbol_name) != 0)
            continue;

        if (sym->st_shndx == SHN_UNDEF)
            continue; // undefined symbol

        return (uint64_t)load_base + sym->st_value;
    }

    return 0;
}