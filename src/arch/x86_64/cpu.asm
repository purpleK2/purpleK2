format ELF64
section '.text' executable align 16

; uint64_t _cpu_get_msr(uint32_t msr)
public _cpu_get_msr
_cpu_get_msr:
    ; first argument's lower 32 bits (-> rdi & 0x0000FFFF)
    mov ecx, edi

    ; reset rax and rdx values
    xor rax, rax
    xor rdx, rdx

    ; ecx = requested MSR
    rdmsr
    ; rax = lower 32 bits of the result
    ; rdx = higher 32 bits

    ; rax |= (rdx << 32)
    shl rdx, 32
    or rax, rdx

    ret

; _cpu_set_msr(uint32_t msr, uint64_t value)
public _cpu_set_msr
_cpu_set_msr:
    ; first argument (MSR)
    mov ecx, edi

    xor rax, rax
    xor rdx, rdx

    ; eax = second argument's lower 32 bits (esi)
    mov rax, rsi

    ; rdx >> 32
    mov rdx, rax
    shr rdx, 32

    ; ecx = requested MSR
    ; eax = lower 32-bits of the value
    ; edx = higher 32-bits
    wrmsr

    ret

; uint64_t _get_cpu_flags()
public _get_cpu_flags
_get_cpu_flags:
    xor rax, rax

    pushfq   ; this pushes the RFLAGS (QWORD)
    pop rax  ; put it in rax

    ret

; void _set_cpu_flags(uint64_t flags)
public _set_cpu_flags
_set_cpu_flags:
    push rdi    ; flags

    popfq       ; put them into RFLAGS :)

    ret

; int _cpu_cpuid(cpuid_ctx_t *ctx)
public _cpu_cpuid
_cpu_cpuid:
    cmp rdi, 0
    je .nullptr

    push rbx
    push rcx
    push rdx

    xor eax, eax
    mov eax, [rdi]
    cpuid

    mov [rdi + 4], eax
    mov [rdi + 8], ebx
    mov [rdi + 12], ecx
    mov [rdi + 16], edx

    pop rdx
    pop rcx
    pop rbx

    mov rax, 0
    ret

.nullptr:
    mov rax, -1
    ret
