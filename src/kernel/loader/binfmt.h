#ifndef BINFMT_H
#define BINFMT_H

#include "memory/vmm/vmm.h"
#include "scheduler/scheduler.h"
#include <stdint.h>

typedef struct binfmt_program {
    pcb_t *pcb;
    int pid;
    vmc_t *vmc;
    const char *path;
    uint64_t entry;
    uint64_t rsp; // to push argv, argc, envp, and auxv
} binfmt_program_t;

typedef struct binfmt_loader {
    const char name[64]; // human readable name

    const uint8_t *magic;
    size_t magic_size;

    int (*load)(const char *path, binfmt_program_t *out);
} binfmt_loader_t;

extern binfmt_loader_t **binfmt_loaders;
extern int binfmt_loader_count;
extern int binfmt_loader_capacity;

int binfmt_register_loader(binfmt_loader_t *loader);
int binfmt_load(const char *path, binfmt_program_t *out);
int binfmt_run(binfmt_program_t *prog);

int binfmt_exec(const char *path);

#endif // BINFMT_H