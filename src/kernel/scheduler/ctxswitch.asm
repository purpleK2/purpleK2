format ELF64

section '.text' executable

public context_switch
public fpu_save
public fpu_restore

; void context_switch(TaskContext **old_ctx, TaskContext *new_ctx)
context_switch:
    ; rdi = &old_ctx, rsi = new_ctx
    push rax
    mov rax, [rdi]              ; load old_ctx

    mov [rax + 0x00], r15
    mov [rax + 0x08], r14
    mov [rax + 0x10], r13
    mov [rax + 0x18], r12
    mov [rax + 0x20], r11
    mov [rax + 0x28], r10
    mov [rax + 0x30], r9
    mov [rax + 0x38], r8
    mov [rax + 0x40], rsi
    mov [rax + 0x48], rdi
    mov [rax + 0x50], rbp
    mov [rax + 0x58], rbx
    mov [rax + 0x60], rdx
    mov [rax + 0x68], rcx
    mov [rax + 0x70], rax       ; save original rax

    ; manually save RIP, CS, RFLAGS, RSP, SS
    lea rdx, [.retpoint]
    mov [rax + 0x78], rdx       ; RIP
    mov rdx, cs
    mov [rax + 0x80], rdx       ; CS
    pushfq
    pop rdx
    mov [rax + 0x88], rdx       ; RFLAGS
    mov rdx, rsp
    mov [rax + 0x90], rdx       ; RSP
    mov rdx, ss
    mov [rax + 0x98], rdx       ; SS

    ; Load new context
    mov rax, rsi
    mov r15, [rax + 0x00]
    mov r14, [rax + 0x08]
    mov r13, [rax + 0x10]
    mov r12, [rax + 0x18]
    mov r11, [rax + 0x20]
    mov r10, [rax + 0x28]
    mov r9,  [rax + 0x30]
    mov r8,  [rax + 0x38]
    mov rsi, [rax + 0x40]
    mov rdi, [rax + 0x48]
    mov rbp, [rax + 0x50]
    mov rbx, [rax + 0x58]
    mov rdx, [rax + 0x60]
    mov rcx, [rax + 0x68]
    mov rax, [rax + 0x70]

    ; Load RIP/CS/RFLAGS/RSP/SS from new context and perform iretq
    mov rdx, [rsi + 0x78] ; RIP
    mov rcx, [rsi + 0x80] ; CS
    mov rbx, [rsi + 0x88] ; RFLAGS
    mov rsi, [rsi + 0x90] ; RSP
    mov rdi, [rsi + 0x98] ; SS

    mov rsp, rsi
    push rdi    ; SS
    push rsi    ; RSP
    push rbx    ; RFLAGS
    push rcx    ; CS
    push rdx    ; RIP
    iretq

.retpoint:
    pop rax
    ret


; void fpu_save(void *ctx)
fpu_save:
    mov rax, rdi
    fxsave [rax]
    ret

; void fpu_restore(void *ctx)
fpu_restore:
    mov rax, rdi
    fxrstor [rax]
    ret
