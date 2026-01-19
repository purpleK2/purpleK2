#ifndef ELFLOADER_H
#define ELFLOADER_H

#include "loader/binfmt.h"
#include "scheduler/scheduler.h"
#include "tsc/tsc.h"
#include <elf/elf.h>

#include <stddef.h>

typedef struct elf_segment {
    uint64_t vaddr;
    uint64_t memsz;
    uint64_t flags;   // PF_R | PF_W | PF_X
} elf_segment_t;

typedef struct elf_program {
    int     pid;
    pcb_t  *pcb;
    tcb_t  *main_thread;
    uint64_t entry;
} elf_program_t;

// TODO: replace with something that has better entropy
static inline uint64_t choose_et_dyn_base(void) {
    uint64_t min = 0x400000;
    uint64_t max = 0x700000000000;

    uint64_t r = (uint64_t)_get_tsc();
    uint64_t base = min + (r % (max - min));

    return ROUND_DOWN(base, PFRAME_SIZE);
}

extern binfmt_loader_t elf_binfmt_loader;

int elf_validate(const Elf64_Ehdr *eh);
int load_elf(const char *path, binfmt_program_t *out);

#endif // ELFLOADER_H