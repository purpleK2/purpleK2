format ELF64

section '.text' executable

public context_load
public context_save

; void context_load(task_regs_t *ctx)
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

; void context_save(task_regs_t *out)
context_save:
    mov [rdi + 0x08], r15
    mov [rdi + 0x10], r14
    mov [rdi + 0x18], r13
    mov [rdi + 0x20], r12

    mov [rdi + 0x48], rbp
    mov [rdi + 0x70], rbx

    mov [rdi + 0xa8], rsp

    ret


public fpu_save
public fpu_restore

; void fpu_save(void *ctx)
fpu_save:
    fxsave [rdi]
    ret

; void fpu_restore(void *ctx)
fpu_restore:
    fxrstor [rdi]
    ret

; void scheduler_idle()
public scheduler_idle
scheduler_idle:
    hlt
    jmp scheduler_idle
