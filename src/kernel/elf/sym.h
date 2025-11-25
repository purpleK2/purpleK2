#ifndef ELF_SYM_H
#define ELF_SYM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <elf/elf.h>

struct SymbolInfo {
    const char *name;
    uint64_t start;
    size_t size;
};

const char *resolve_symbol_name(void *elf_data, size_t size, uint64_t addr);

uint64_t resolve_symbol_addr(void *elf_data, size_t size,
                             const char *symbol_name);

uint64_t resolve_module_symbol(Elf64_Ehdr *ehdr, const char *symbol_name,
                               uint8_t *load_base);

bool resolve_symbol(void *elf_data, size_t size, uint64_t addr,
                    struct SymbolInfo *out);

#endif // ELF_SYM_H
