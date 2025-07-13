format ELF64
section '.text' executable align 16

; void _invalidate(uint64_t virtual)
public _invalidate
_invalidate:
	invlpg [rdi]
	ret

; void _load_pml4(uint64_t *pml4_base)
public _load_pml4
_load_pml4:
	mov cr3, rdi

	ret

; uint64_t _get_pml4()
public _get_pml4
_get_pml4:
	mov rax, cr3

	ret
