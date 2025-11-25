[bits 64]

global _enable_interrupts
_enable_interrupts:
    sti
    ret

global _disable_interrupts
_disable_interrupts:
    cli
    ret
