#ifndef MODULE_LOADER_H
#define MODULE_LOADER_H

#include <module/mod.h>
#include <module/modinfo.h>

#include <elf/sym.h>

#define ELF_SHDR(ehdr)         ((Elf64_Shdr *)((uintptr_t)ehdr + ehdr->e_shoff))
#define ELF_SECTION(ehdr, idx) ((Elf64_Shdr *)&ELF_SHDR(ehdr)[idx])
#define ELF_PHDR(ehdr, idx)                                                    \
    ((Elf64_Phdr *)((uintptr_t)ehdr + ehdr->e_phoff + ehdr->e_phentsize * idx))

mod_t *load_module(const char *file_path);

#endif // MODULE_LOADER_H