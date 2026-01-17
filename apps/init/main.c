// main.c
// freestanding userspace program for your OS

typedef unsigned long  uint64_t;
typedef long           int64_t;
typedef unsigned long  size_t;

/* syscall numbers (from your asm comments) */
#define SYS_EXIT  0
#define SYS_OPEN  1
#define SYS_WRITE 3

static inline uint64_t syscall3(
    uint64_t num,
    uint64_t a1,
    uint64_t a2,
    uint64_t a3
) {
    uint64_t ret;
    __asm__ volatile (
        "int $0x80"
        : "=a"(ret)
        : "a"(num), "D"(a1), "S"(a2), "d"(a3)
        : "memory"
    );
    return ret;
}

static inline uint64_t syscall2(
    uint64_t num,
    uint64_t a1,
    uint64_t a2
) {
    uint64_t ret;
    __asm__ volatile (
        "int $0x80"
        : "=a"(ret)
        : "a"(num), "D"(a1), "S"(a2)
        : "memory"
    );
    return ret;
}

static inline uint64_t syscall1(
    uint64_t num,
    uint64_t a1
) {
    uint64_t ret;
    __asm__ volatile (
        "int $0x80"
        : "=a"(ret)
        : "a"(num), "D"(a1)
        : "memory"
    );
    return ret;
}

static const char filename[] = "/dev/com1";
static char buffer[] = "RELA test OK\n";
static char *buffer_ptr = buffer;

void _start(void) {
    uint64_t fd = syscall2(SYS_OPEN, (uint64_t)filename, 0);
    syscall3(SYS_WRITE, fd, (uint64_t)buffer_ptr, sizeof(buffer)-1);
    syscall1(SYS_EXIT, 69);

    for(;;) __asm__("hlt");
}
