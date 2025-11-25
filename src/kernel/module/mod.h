#ifndef MOD_H
#define MOD_H

#include <module/modinfo.h>

#include <stddef.h>

typedef struct _mod {
    modinfo_t *modinfo;
    void *base_address;
    void *end_address;
    size_t image_size;
    void *ehdr;
    void (*entry_point)(void);
    void (*exit_point)(void);
} mod_t;

#endif // MOD_H