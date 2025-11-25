# PurpleK2 Syscalls
Some docs for systemcalls in the PurpleK2 kernel.

## General information

System calls can be triggered using either the `syscall` instruction or with interrupt `0x80` (which can be triggered using `int 0x80` in assembly). Arguments are passed to the kernel using the ABI below. There isnt a need for any stack alignment.

## Argument Passing / ABI
- The **Syscall Number** is passed using the **`RAX`** register
- The **Syscall Return** value is also passed using the **`RAX`** register
- The **1. Syscall Argument** is passed using the **`RDI`** register
- The **2. Syscall Argument** is passed using the **`RSI`** register
- The **3. Syscall Argument** is passed using the **`RDX`** register
- The **4. Syscall Argument** is passed using the **`R8`** register
- The **5. Syscall Argument** is passed using the **`R9`** register
- The **5. Syscall Argument** is passed using the **`R10`** register

## Syscall Table
A complete table of all syscalls

| Syscall Name | Syscall Description | Syscall Number (%rax) | Return Value (%rax)  | Arg 1 (%rdi)  | Arg 2 (%rsi) | Arg 3 (%rdx) | Arg 4 (%r8) | Arg 5 (%r9) | Arg 6 (%r10) |
|--------------|---------------------------|-----------------------|----------------------|---------------|--------------|--------------|-------------|-------------|--------------|
| exit | Exits the current process | 0 | / | int exit_code | / | / | / | / | / |
| open | Opens a file from the VFS | 1 | int fd (File Descriptor of the opened file or -1 on error) | char* path | int mode | / | / | / | / |
| read | Reads the contents of a file | 2 | int bytes_read (or error) | int fd | void *buffer | int size | / | / | / |
| write | Writes data to a file | 3 | int bytes_written (or error) | int fd | void* out | int size | / | / | / |
| close | Closes a file descriptor | 4 | int return (0 on success or else error) | int fd | / | / | / | / | / | 
| ioctl | Sends an ioctl command to the fd | 5 | int ioctl_call_return | int fd | int request | void *arg | / | / | / |
| seek | Seeks the fd to a specific offset | 6 | int new_offset | int fd | int whence | int offset | / | / | / |
| fcntl | Performs an operation on an file descriptor | 7 | int fd | int op | void* arg | / | / | / |