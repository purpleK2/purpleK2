format ELF64

section '.text' executable

public context_load
public context_save

; void context_load(task_regs_t *ctx)
context_load:
    mov rsp, rdi

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rsi
    pop rdi
    pop rbp
    pop rdx
    pop rcx
    pop rbx
    pop rax

    iretq   ; pops RIP, CS, RFLAGS, RSP, SS

; void context_save(task_regs_t *out)
context_save:
    ; saving callee-saved registers? i hope: ))
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
