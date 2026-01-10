#ifndef ELFLOADER_H
#define ELFLOADER_H

#include "scheduler/scheduler.h"
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
    uint64_t user_stack_top;
    size_t   user_stack_pages;
} elf_program_t;


int elf_validate(const Elf64_Ehdr *eh);
int load_elf(const char *path, elf_program_t *out);

#endif // ELFLOADER_H