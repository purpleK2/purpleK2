format ELF64

section '.text' executable

public context_load

; void context_load(registers_t *ctx)
context_load:
    mov r15, [rdi + 0x10]
    mov r14, [rdi + 0x18]
    mov r13, [rdi + 0x20]
    mov r12, [rdi + 0x28]
    mov r11, [rdi + 0x30]
    mov r10, [rdi + 0x38]
    mov r9,  [rdi + 0x40]
    mov r8,  [rdi + 0x48]
    mov rbp, [rdi + 0x50]
    mov rsi, [rdi + 0x60]
    mov rdx, [rdi + 0x68]
    mov rcx, [rdi + 0x70]
    mov rbx, [rdi + 0x78]

    ; Load segment selector (now at +0x08)
    mov cx, [rdi + 0x08]
    mov ds, cx
    mov es, cx

    ; Load rax
    mov rax, [rdi + 0x80]

    ; Reload rcx (now at +0x70)
    mov rcx, [rdi + 0x70]

    ; Stack pointer (was 0x90 → now 0x98)
    lea rsp, [rdi + 0x98]

    ; rdi (was 0x50 → now 0x58)
    mov rdi, [rdi + 0x58]

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
