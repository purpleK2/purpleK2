format ELF64
section '.text' executable align 16

; void _load_gdt(gdt_pointer_t* descriptor)
public _load_gdt
_load_gdt:
    lgdt [rdi]
    ret

; void _reload_segments(uint64_t cs, uint64_t ds)
public _reload_segments
_reload_segments:
    push rdi        ; cs (rdi & 0xFF)

    lea rax, [.reload_cs]
    push rax

    retfq
.reload_cs:
    mov ax, si      ; ds
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    ret
