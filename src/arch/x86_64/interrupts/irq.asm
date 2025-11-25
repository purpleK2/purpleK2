format ELF64
section '.text' executable align 16

public _enable_interrupts
_enable_interrupts:
    sti
    ret

public _disable_interrupts
_disable_interrupts:
    cli
    ret
