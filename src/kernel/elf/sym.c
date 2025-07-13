#include "sym.h"

#include <string.h>

const char *resolve_symbol_name(void *elf_data, size_t size, uint64_t addr) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_data;
    if (memcmp(ehdr->e_ident,
               "\x7f"
               "ELF",
               4) != 0 ||
        ehdr->e_ident[4] != 2)
        return 0;

    Elf64_Shdr *shdrs = (Elf64_Shdr *)((uint8_t *)elf_data + ehdr->e_shoff);
    Elf64_Shdr *shstrtab_hdr = &shdrs[ehdr->e_shstrndx];
    const char *shstrtab     = (const char *)elf_data + shstrtab_hdr->sh_offset;

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
        uint8_t type   = sym->st_info & 0x0F;
        if (type == STT_FUNC && addr >= sym->st_value &&
            addr < sym->st_value + sym->st_size) {
            return strtab + sym->st_name;
        }
    }

    return 0;
}
