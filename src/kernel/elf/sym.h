#ifndef ELF_SYM_H
#define ELF_SYM_H

#include <stddef.h>
#include <stdint.h>

#include <elf/elf.h>

const char *resolve_symbol_name(void *elf_data, size_t size, uint64_t addr);

uint64_t
resolve_symbol_addr(void *elf_data, size_t size,
                    const char *symbol_name); // so this is like for kernel
                                              // modules / drivers because :3c

uint64_t resolve_module_symbol(void *elf_data, Elf64_Shdr *shdrs,
                               const char *symbol_name, uint8_t *load_base);

#endif // ELF_SYM_H
