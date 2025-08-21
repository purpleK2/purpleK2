format ELF64

section '.text' executable

public context_load
public context_save

; void context_load(task_regs_t *ctx)
context_load:
    mov r15, [rdi]
    mov r14, [rdi + 8h]
    mov r13, [rdi + 10h]
    mov r12, [rdi + 18h]

    mov rbp, [rdi + 50h]
    mov rbx, [rdi + 68h]

    mov rsp, [rdi + 90h]
    ret

; void context_save(task_regs_t *out)
context_save:
    mov [rdi], r15
    mov [rdi + 8h], r14
    mov [rdi + 10h], r13
    mov [rdi + 18h], r12

    mov [rdi + 50h], rbp
    mov [rdi + 68h], rbx

    mov [rdi + 90h], rsp
    
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
