format ELF64

section '.text' executable

public context_load
public context_save

; void context_load(task_regs_t *ctx)
context_load:
    mov r15, [rdi + 08h]
    mov r14, [rdi + 10h]
    mov r13, [rdi + 18h]
    mov r12, [rdi + 20h]

    mov [rdi + 48h], rbp
    mov [rdi + 70h], rbx

    mov rsp, rdi
    add rsp, 90h

    iretq

; void context_save(task_regs_t *out)
context_save:
    mov [rdi + 08h], r15
    mov [rdi + 10h], r14
    mov [rdi + 18h], r13
    mov [rdi + 20h], r12

    mov [rdi + 48h], rbp
    mov [rdi + 68h], rbx

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
