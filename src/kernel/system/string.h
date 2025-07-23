#ifndef STRING_H
#define STRING_H 1

#include <kernel.h>
#include <limine.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
    GCC and Clang reserve the right to generate calls to the following
    4 functions even if they are not directly called.
    Implement them as the C specification mandates.
    DO NOT remove or rename these functions, or stuff will eventually break!
    They CAN be moved to a different .c file.
*/
void *memcpy(void *dest, const void *src, size_t n);
void *memset(void *s, int c, size_t n);
void *memmove(void *dest, const void *src, size_t n);
int memcmp(const void *s1, const void *s2, size_t n);

size_t strlen(const char *s);
int strcmp(const char *s1, const char *s2);
int strncmp(const char *s1, const char *s2, size_t len);

char *strstr(const char *s1, const char *s2);

void *memchr(const void *str, int c, size_t n);

char *strncpy(char *dest, const char *src, size_t n);
char *strdup(const char *s);
char *strtok(char *str, const char *delim);
char *strchr(const char *str, int c);
char *strrchr(const char *s, int c);
char *strtok_r(char *str, const char *delim, char **saveptr);
void strcpy(char dest[], const char source[]);

static const char *const memory_block_type[] = {"USABLE",
                                                "RESERVED",
                                                "ACPI_RECLAIMABLE",
                                                "ACPI_NVS",
                                                "BAD",
                                                "BOOTLOADER_RECLAIMABLE",
                                                "KERNEL_AND_MODULES",
                                                "FRAMEBUFFER"};

uint64_t strtoull(const char *str, const char **endptr, int base);

// atoi but you specify the length of the string
int natoi(char *s, size_t n);
// natoi but for strings with hex numbers
int nxatoi(char *s, size_t n);

#endif
