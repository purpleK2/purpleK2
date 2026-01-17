format ELF64

section '.text' executable

public context_load

; void context_load(registers_t *ctx)
context_load:
    mov r15, [rdi + 0x08]
    mov r14, [rdi + 0x10]
    mov r13, [rdi + 0x18]
    mov r12, [rdi + 0x20]

    mov rbp, [rdi + 0x48]
    mov rbx, [rdi + 0x70]

    mov rsp, rdi
    add rsp, 0x90

    iretq

public fpu_save
public fpu_restore

; void fpu_save(registers_t *ctx)
fpu_save:
    fxsave [rdi]
    ret

; void fpu_restore(registers_t *ctx)
fpu_restore:
    fxrstor [rdi]
    ret

; void scheduler_idle()
public scheduler_idle
scheduler_idle:
    hlt
    jmp scheduler_idle
