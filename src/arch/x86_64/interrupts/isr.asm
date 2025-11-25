extern isr_handler

isr_common:
    ; push all registers
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    ; push ds
    mov rbp, ds
    push rbp

    mov bx, 0x10
    mov ds, bx
    mov es, bx
    mov fs, bx
    mov gs, bx
    mov ss, bx

    mov rdi, rsp
    call isr_handler

    pop rbp
    mov ds, ebp
    mov es, ebp
    mov fs, ebp
    mov gs, ebp
    mov ss, ebp

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax

    add rsp, 16 ; pop error code and interrupt number
    iretq

%macro isr_err_stub 1
global isr_stub_%+%1
isr_stub_%+%1:
    ; error code gets pushed to the stack
    push %1             ; interrupt number
    jmp isr_common
    iretq
%endmacro

%macro isr_no_err_stub 1
global isr_stub_%+%1
isr_stub_%+%1:
    push 0              ; dummy error code
    push %1             ; interrupt number
    jmp isr_common
    iretq
%endmacro

isr_no_err_stub 0
isr_no_err_stub 1
isr_no_err_stub 2
isr_no_err_stub 3
isr_no_err_stub 4
isr_no_err_stub 5
isr_no_err_stub 6
isr_no_err_stub 7
isr_err_stub    8
isr_no_err_stub 9
isr_err_stub    10
isr_err_stub    11
isr_err_stub    12
isr_err_stub    13
isr_err_stub    14
isr_no_err_stub 15
isr_no_err_stub 16
isr_err_stub    17
isr_no_err_stub 18
isr_no_err_stub 19
isr_no_err_stub 20
isr_err_stub    21
isr_no_err_stub 22
isr_no_err_stub 23
isr_no_err_stub 24
isr_no_err_stub 25
isr_no_err_stub 26
isr_no_err_stub 27
isr_no_err_stub 28
isr_err_stub    29
isr_err_stub    30
isr_no_err_stub 31
isr_no_err_stub 32
isr_no_err_stub 33
isr_no_err_stub 34
isr_no_err_stub 35
isr_no_err_stub 36
isr_no_err_stub 37
isr_no_err_stub 38
isr_no_err_stub 39
isr_no_err_stub 40
isr_no_err_stub 41
isr_no_err_stub 42
isr_no_err_stub 43
isr_no_err_stub 44
isr_no_err_stub 45
isr_no_err_stub 46
isr_no_err_stub 47
isr_no_err_stub 48
isr_no_err_stub 49
isr_no_err_stub 50
isr_no_err_stub 51
isr_no_err_stub 52
isr_no_err_stub 53
isr_no_err_stub 54
isr_no_err_stub 55
isr_no_err_stub 56
isr_no_err_stub 57
isr_no_err_stub 58
isr_no_err_stub 59
isr_no_err_stub 60
isr_no_err_stub 61
isr_no_err_stub 62
isr_no_err_stub 63
isr_no_err_stub 64
isr_no_err_stub 65
isr_no_err_stub 66
isr_no_err_stub 67
isr_no_err_stub 68
isr_no_err_stub 69
isr_no_err_stub 70
isr_no_err_stub 71
isr_no_err_stub 72
isr_no_err_stub 73
isr_no_err_stub 74
isr_no_err_stub 75
isr_no_err_stub 76
isr_no_err_stub 77
isr_no_err_stub 78
isr_no_err_stub 79
isr_no_err_stub 80
isr_no_err_stub 81
isr_no_err_stub 82
isr_no_err_stub 83
isr_no_err_stub 84
isr_no_err_stub 85
isr_no_err_stub 86
isr_no_err_stub 87
isr_no_err_stub 88
isr_no_err_stub 89
isr_no_err_stub 90
isr_no_err_stub 91
isr_no_err_stub 92
isr_no_err_stub 93
isr_no_err_stub 94
isr_no_err_stub 95
isr_no_err_stub 96
isr_no_err_stub 97
isr_no_err_stub 98
isr_no_err_stub 99
isr_no_err_stub 100
isr_no_err_stub 101
isr_no_err_stub 102
isr_no_err_stub 103
isr_no_err_stub 104
isr_no_err_stub 105
isr_no_err_stub 106
isr_no_err_stub 107
isr_no_err_stub 108
isr_no_err_stub 109
isr_no_err_stub 110
isr_no_err_stub 111
isr_no_err_stub 112
isr_no_err_stub 113
isr_no_err_stub 114
isr_no_err_stub 115
isr_no_err_stub 116
isr_no_err_stub 117
isr_no_err_stub 118
isr_no_err_stub 119
isr_no_err_stub 120
isr_no_err_stub 121
isr_no_err_stub 122
isr_no_err_stub 123
isr_no_err_stub 124
isr_no_err_stub 125
isr_no_err_stub 126
isr_no_err_stub 127
isr_no_err_stub 128
isr_no_err_stub 129
isr_no_err_stub 130
isr_no_err_stub 131
isr_no_err_stub 132
isr_no_err_stub 133
isr_no_err_stub 134
isr_no_err_stub 135
isr_no_err_stub 136
isr_no_err_stub 137
isr_no_err_stub 138
isr_no_err_stub 139
isr_no_err_stub 140
isr_no_err_stub 141
isr_no_err_stub 142
isr_no_err_stub 143
isr_no_err_stub 144
isr_no_err_stub 145
isr_no_err_stub 146
isr_no_err_stub 147
isr_no_err_stub 148
isr_no_err_stub 149
isr_no_err_stub 150
isr_no_err_stub 151
isr_no_err_stub 152
isr_no_err_stub 153
isr_no_err_stub 154
isr_no_err_stub 155
isr_no_err_stub 156
isr_no_err_stub 157
isr_no_err_stub 158
isr_no_err_stub 159
isr_no_err_stub 160
isr_no_err_stub 161
isr_no_err_stub 162
isr_no_err_stub 163
isr_no_err_stub 164
isr_no_err_stub 165
isr_no_err_stub 166
isr_no_err_stub 167
isr_no_err_stub 168
isr_no_err_stub 169
isr_no_err_stub 170
isr_no_err_stub 171
isr_no_err_stub 172
isr_no_err_stub 173
isr_no_err_stub 174
isr_no_err_stub 175
isr_no_err_stub 176
isr_no_err_stub 177
isr_no_err_stub 178
isr_no_err_stub 179
isr_no_err_stub 180
isr_no_err_stub 181
isr_no_err_stub 182
isr_no_err_stub 183
isr_no_err_stub 184
isr_no_err_stub 185
isr_no_err_stub 186
isr_no_err_stub 187
isr_no_err_stub 188
isr_no_err_stub 189
isr_no_err_stub 190
isr_no_err_stub 191
isr_no_err_stub 192
isr_no_err_stub 193
isr_no_err_stub 194
isr_no_err_stub 195
isr_no_err_stub 196
isr_no_err_stub 197
isr_no_err_stub 198
isr_no_err_stub 199
isr_no_err_stub 200
isr_no_err_stub 201
isr_no_err_stub 202
isr_no_err_stub 203
isr_no_err_stub 204
isr_no_err_stub 205
isr_no_err_stub 206
isr_no_err_stub 207
isr_no_err_stub 208
isr_no_err_stub 209
isr_no_err_stub 210
isr_no_err_stub 211
isr_no_err_stub 212
isr_no_err_stub 213
isr_no_err_stub 214
isr_no_err_stub 215
isr_no_err_stub 216
isr_no_err_stub 217
isr_no_err_stub 218
isr_no_err_stub 219
isr_no_err_stub 220
isr_no_err_stub 221
isr_no_err_stub 222
isr_no_err_stub 223
isr_no_err_stub 224
isr_no_err_stub 225
isr_no_err_stub 226
isr_no_err_stub 227
isr_no_err_stub 228
isr_no_err_stub 229
isr_no_err_stub 230
isr_no_err_stub 231
isr_no_err_stub 232
isr_no_err_stub 233
isr_no_err_stub 234
isr_no_err_stub 235
isr_no_err_stub 236
isr_no_err_stub 237
isr_no_err_stub 238
isr_no_err_stub 239
isr_no_err_stub 240
isr_no_err_stub 241
isr_no_err_stub 242
isr_no_err_stub 243
isr_no_err_stub 244
isr_no_err_stub 245
isr_no_err_stub 246
isr_no_err_stub 247
isr_no_err_stub 248
isr_no_err_stub 249
isr_no_err_stub 250
isr_no_err_stub 251
isr_no_err_stub 252
isr_no_err_stub 253
isr_no_err_stub 254
isr_no_err_stub 255

global isr_stub_table
isr_stub_table:
%assign i 0
%rep    256
    dq isr_stub_%+i
%assign i i+1
%endrep

global _hcf
_hcf:
    cli
    hlt
