format ELF64
section '.text' executable align 16

; void _outb(uint16_t port, uint8_t val)
; rdi = port
; rsi = val
public _outb
_outb:
	mov dx, di
	mov ax, si

	; how it works (just so i don't have to search it again)
	; out PORT, VALUE
	out dx, al

	ret

; void _outw(uint16_t port, uint16_t val)
public _outw
_outw:
    mov dx, di
    mov ax, si

    out dx, ax

    ret

; void _outd(uint16_t port, uint32_t val)
public _outd
_outd:
    mov dx, di
    mov ax, si

    out dx, eax

    ret

; uint8_t _inb(uint16_t port)
; rdi = port
public _inb
_inb:
	mov dx, di

	xor ax, ax

	; how it works (just so i don't have to search it again)
	; in (some register where the value will be saved), PORT
	in al, dx

	ret

; uint16_t _inw(uint16_t port)
public _inw
_inw:
    mov dx, di
    xor ax, ax

    in ax, dx

    ret

; uint32_t _ind(uint16_t port)
public _ind
_ind:
    mov dx, di
    xor ax, ax

    in eax, dx

    ret

public _outl
public _inl
	
	; Function: _outl
	; Description: Writes a 32-bit value to the specified port.
	; Arguments:
	;   RDI - port (uint16_t)
	;   RSI - value (uint32_t)
_outl:
	; Move the port to the DX register (lower 16 bits)
	mov dx, di          ; Move the 16-bit port number to DX
	; Move the value to the EAX register (lower 32 bits)
	mov eax, esi        ; Move the 32-bit value to EAX
	; Perform the out instruction
	out dx, eax         ; Output the value in EAX to the port in DX
	ret                  ; Return from the function
	
; Function: _inl
; Description: Reads a 32-bit value from the specified port.
; Arguments:
;   RDI - port (uint16_t)
; Returns:
;   RAX - value (uint32_t)
_inl:
	; Move the port to the DX register (lower 16 bits)
	mov dx, di          ; Move the 16-bit port number to DX
	; Perform the in instruction
	in eax, dx          ; Input a 32-bit value from the port in DX to EAX
	ret                  ; Return from the function

; void _io_wait(void)
public _io_wait
_io_wait:
	push rdi
	push rsi

	mov rdi, 0x80
	mov rsi, 0x0

	call _outb

	pop rsi
	pop rdi

	ret
