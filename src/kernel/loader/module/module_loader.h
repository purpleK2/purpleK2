#ifndef MODULE_LOADER_H
#define MODULE_LOADER_H

#include <module/mod.h>
#include <module/modinfo.h>

#include <elf/sym.h>

mod_t *load_module(const char *file_path);

const struct modinfo_t *load_driver_info(void *elf_data);

#endif // MODULE_LOADER_H