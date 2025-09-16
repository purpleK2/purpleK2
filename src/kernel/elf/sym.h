#ifndef ELF_SYM_H
#define ELF_SYM_H

#include <stddef.h>
#include <stdint.h>

#define EI_NIDENT  16
#define SHT_SYMTAB 2
#define SHT_STRTAB 3
#define STT_FUNC   2

#define EI_CLASS   4 // e_ident[] index for file class
#define ELFCLASS64 2 // 64-bit ELF

#define SHT_SYMTAB 2  // Symbol table section
#define SHT_STRTAB 3  // String table section
#define SHT_DYNSYM 11 // Dynamic symbol table section

// Symbol bindings
#define STB_LOCAL  0
#define STB_GLOBAL 1
#define STB_WEAK   2

// Special section indices
#define SHN_UNDEF 0

// Macro to extract symbol binding/type from st_info
#define ELF64_ST_BIND(i) ((i) >> 4)
#define ELF64_ST_TYPE(i) ((i) & 0x0F)

typedef struct {
    unsigned char e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} Elf64_Shdr;

typedef struct {
    uint32_t st_name;
    unsigned char st_info;
    unsigned char st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} Elf64_Sym;

const char *resolve_symbol_name(void *elf_data, size_t size, uint64_t addr);

uint64_t
resolve_symbol_addr(void *elf_data, size_t size,
                    const char *symbol_name); // so this is like for kernel
                                              // modules / drivers because :3c

#endif // ELF_SYM_H
