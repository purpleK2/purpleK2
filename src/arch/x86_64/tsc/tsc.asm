format ELF64
section '.text' executable align 16

public _get_tsc
_get_tsc:
    rdtsc
    shl rdx, 32
    or  rax, rdx
    ret
