#include "sse.h"

#include <cpu.h>

#include <stdio.h>

bool sse_enabled = false;

void init_sse() {

    if (!fpu_enabled) {
        init_fpu();
    }

    if (!check_sse()) {
        kprintf_panic("SSE1.0 not available!\n");
        _hcf();
    }

    if (!check_sse2()) {
        kprintf_panic("SSE2 not available!\n");
        _hcf();
    }

    if (!check_fxsr()) {
        kprintf_panic("FXSR not available!\n");
        _hcf();
    }

    asm volatile("mov %%cr4, %%rax\n"
                 "or  $(1 << 9), %%rax\n"  // OSFXSR
                 "or  $(1 << 10), %%rax\n" // OSXMMEXCPT
                 "mov %%rax, %%cr4\n" ::
                     : "rax");

    sse_enabled = true;
}