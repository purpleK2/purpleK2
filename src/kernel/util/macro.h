#ifndef MACRO_H
#define MACRO_H 1

#define SECTION(name) __attribute__((section(name)))
#define USED          __attribute__((used))
#define PACKED        __attribute__((packed))
#define ALIGNED(n)    __attribute__((aligned(n)))

#define stringify(sumthin) #sumthin

#define BIT_SET(x, bit)   ((x) |= (1ULL << (bit)))
#define BIT_CLEAR(x, bit) ((x) &= ~(1ULL << (bit)))
#define BIT_GET(x, bit)   (((x) >> (bit)) & 1)

#define FLAG_SET(x, flag)   ((x) |= (flag))
#define FLAG_UNSET(x, flag) ((x) &= ~(flag))

#define ROUND_DOWN(n, a) ((n) & ~((a) - 1))
#define ROUND_UP(n, a)   (((n) + (a) - 1) & ~((a) - 1))

#define UNUSED(x) ((void)(x))

#define ABS(x) ((x) >= 0 ? (x) : -(x))

#endif // MACRO_H