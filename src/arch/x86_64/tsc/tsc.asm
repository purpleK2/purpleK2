[bits 64]

global _get_tsc
_get_tsc:
    rdtsc
    shl rdx, 32
    or  rax, rdx
    ret
