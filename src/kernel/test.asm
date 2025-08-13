format ELF64

filename db "/dev/com1", 0
what_to_write db "hello from process\n", 0


section '.text' executable align 16

public __sched_test
__sched_test:
    mov rax, 1
    mov rdi, filename
    mov rsi, 0
    int 0x80

    mov rdi, rax
    mov rax, 3
    mov rsi, what_to_write
    mov rdx, 20
    int 0x80

    mov rax, 0
    mov rdi, 0
    int 0x80

    ret ; just in case