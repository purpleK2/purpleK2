// main.c
// freestanding userspace program for your OS

#include <stdint.h>
typedef unsigned long  uint64_t;
typedef long           int64_t;
typedef unsigned long  size_t;
typedef unsigned int   uint32_t;

/* syscall numbers */
#define SYS_EXIT  0
#define SYS_OPEN  1
#define SYS_WRITE 3

/* auxv types */
#define AT_NULL         0
#define AT_IGNORE       1
#define AT_EXECFD       2
#define AT_PHDR         3
#define AT_PHENT        4
#define AT_PHNUM        5
#define AT_PAGESZ       6
#define AT_BASE         7
#define AT_FLAGS        8
#define AT_ENTRY        9
#define AT_NOTELF       10
#define AT_UID          11
#define AT_EUID         12
#define AT_GID          13
#define AT_EGID         14
#define AT_PLATFORM     15
#define AT_HWCAP        16
#define AT_CLKTCK       17
#define AT_SECURE       23
#define AT_RANDOM       25
#define AT_HWCAP2       26
#define AT_EXECFN       31

typedef struct {
    uint64_t a_type;
    union {
        uint64_t a_val;
    } a_un;
} Elf64_auxv_t;

static inline uint64_t syscall3(uint64_t num, uint64_t a1, uint64_t a2, uint64_t a3) {
    uint64_t ret;
    __asm__ volatile (
        "int $0x80"
        : "=a"(ret)
        : "a"(num), "D"(a1), "S"(a2), "d"(a3)
        : "memory"
    );
    return ret;
}

static inline uint64_t syscall2(uint64_t num, uint64_t a1, uint64_t a2) {
    uint64_t ret;
    __asm__ volatile (
        "int $0x80"
        : "=a"(ret)
        : "a"(num), "D"(a1), "S"(a2)
        : "memory"
    );
    return ret;
}

static inline uint64_t syscall1(uint64_t num, uint64_t a1) {
    uint64_t ret;
    __asm__ volatile (
        "int $0x80"
        : "=a"(ret)
        : "a"(num), "D"(a1)
        : "memory"
    );
    return ret;
}

static const char filename[] = "/dev/e9";

__thread uint64_t thread_local_var = 67;

static size_t strlen(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

static void print(uint64_t fd, const char *str) {
    syscall3(SYS_WRITE, fd, (uint64_t)str, strlen(str));
}

static void print_hex(uint64_t fd, uint64_t value) {
    char buf[19]; // "0x" + 16 hex digits + null
    buf[0] = '0';
    buf[1] = 'x';
    
    for (int i = 15; i >= 0; i--) {
        uint64_t nibble = (value >> (i * 4)) & 0xF;
        buf[17 - i] = (nibble < 10) ? ('0' + nibble) : ('a' + nibble - 10);
    }
    buf[18] = '\0';
    
    syscall3(SYS_WRITE, fd, (uint64_t)buf, 18);
}

static void print_dec(uint64_t fd, uint64_t value) {
    char buf[21]; // max 20 digits for uint64_t + null
    int i = 19;
    buf[20] = '\0';
    
    if (value == 0) {
        buf[i--] = '0';
    } else {
        while (value > 0) {
            buf[i--] = '0' + (value % 10);
            value /= 10;
        }
    }
    
    syscall3(SYS_WRITE, fd, (uint64_t)&buf[i + 1], 19 - i);
}

static const char *auxv_type_name(uint64_t type) {
    switch (type) {
        case AT_NULL:     return "AT_NULL";
        case AT_IGNORE:   return "AT_IGNORE";
        case AT_EXECFD:   return "AT_EXECFD";
        case AT_PHDR:     return "AT_PHDR";
        case AT_PHENT:    return "AT_PHENT";
        case AT_PHNUM:    return "AT_PHNUM";
        case AT_PAGESZ:   return "AT_PAGESZ";
        case AT_BASE:     return "AT_BASE";
        case AT_FLAGS:    return "AT_FLAGS";
        case AT_ENTRY:    return "AT_ENTRY";
        case AT_NOTELF:   return "AT_NOTELF";
        case AT_UID:      return "AT_UID";
        case AT_EUID:     return "AT_EUID";
        case AT_GID:      return "AT_GID";
        case AT_EGID:     return "AT_EGID";
        case AT_PLATFORM: return "AT_PLATFORM";
        case AT_HWCAP:    return "AT_HWCAP";
        case AT_CLKTCK:   return "AT_CLKTCK";
        case AT_SECURE:   return "AT_SECURE";
        case AT_RANDOM:   return "AT_RANDOM";
        case AT_HWCAP2:   return "AT_HWCAP2";
        case AT_EXECFN:   return "AT_EXECFN";
        default:          return "AT_UNKNOWN";
    }
}

void main(uintptr_t *stack_ptr) {
    uint64_t *stack = (uint64_t *)stack_ptr;
    uint64_t fd = syscall2(SYS_OPEN, (uint64_t)filename, 0);
    
    uint64_t argc = stack[0];
    
    char **argv = (char **)&stack[1];
    
    char **envp = (char **)&stack[argc + 2];
    
    char **env_ptr = envp;
    while (*env_ptr != 0) {
        env_ptr++;
    }
    env_ptr++;
    
    Elf64_auxv_t *auxv = (Elf64_auxv_t *)env_ptr;

    print(fd, "Stack pointer (rsp) = ");
    print_hex(fd, (unsigned long long)stack);
    print(fd, "\r\n");
    
    print(fd, "argc = ");
    print_dec(fd, argc);
    print(fd, "\r\n");
    
    print(fd, "\r\nArguments:\r\n");
    for (uint64_t i = 0; i < argc; i++) {
        print(fd, "  argv[");
        print_dec(fd, i);
        print(fd, "] = \"");
        print(fd, argv[i]);
        print(fd, "\"\r\n");
    }
    
    print(fd, "\r\nEnvironment:\r\n");
    for (int i = 0; envp[i] != 0; i++) {
        print(fd, "  envp[");
        print_dec(fd, i);
        print(fd, "] = \"");
        print(fd, envp[i]);
        print(fd, "\"\r\n");
    }
    
    print(fd, "\r\nAuxiliary Vector:\r\n");
    const char *execfn = 0;
    for (int i = 0; auxv[i].a_type != AT_NULL; i++) {
        print(fd, "  ");
        print(fd, auxv_type_name(auxv[i].a_type));
        print(fd, " = ");
        
        if (auxv[i].a_type == AT_EXECFN) {
            execfn = (const char *)auxv[i].a_un.a_val;
            print(fd, "\"");
            print(fd, execfn);
            print(fd, "\"");
        } else if (auxv[i].a_type == AT_PLATFORM) {
            print(fd, "\"");
            print(fd, (const char *)auxv[i].a_un.a_val);
            print(fd, "\"");
        } else {
            print_hex(fd, auxv[i].a_un.a_val);
        }
        print(fd, "\r\n");
    }
    
    if (argc > 0) {
        print(fd, "argv[0] = \"");
        print(fd, argv[0]);
        print(fd, "\"\r\n");
    }
    
    if (execfn) {
        print(fd, "AT_EXECFN = \"");
        print(fd, execfn);
        print(fd, "\"\r\n");
    }
    
    print(fd, "Initial thread_local_var = ");
    print_dec(fd, thread_local_var);
    print(fd, "\r\n");
    
    thread_local_var += 33;
    
    print(fd, "After += 33: thread_local_var = ");
    print_dec(fd, thread_local_var);
    print(fd, "\r\n");
    
    syscall1(SYS_EXIT, thread_local_var);
    
    for(;;) __asm__("hlt");
}