#include "string.h"
#include "stdio.h"
#include <io.h>
#include <memory/heap/kheap.h>

// GCC and Clang reserve the right to generate calls to the following
// 4 functions even if they are not directly called.
// Implement them as the C specification mandates.
// DO NOT remove or rename these functions, or stuff will eventually break!
// They CAN be moved to a different .c file.

void *memcpy(void *dest, const void *src, size_t n) {
    // debugf("memcpy(%p, %p, %zu)\n", dest, src, n);
    uint8_t *pdest      = (uint8_t *)dest;
    const uint8_t *psrc = (const uint8_t *)src;

    for (size_t i = 0; i < n; i++) {
        pdest[i] = psrc[i];
    }

    return dest;
}

void *memset(void *s, int c, size_t n) {
    uint8_t *p = (uint8_t *)s;

    for (size_t i = 0; i < n; i++) {
        p[i] = (uint8_t)c;
    }

    return s;
}

void *memmove(void *dest, const void *src, size_t n) {
    uint8_t *pdest      = (uint8_t *)dest;
    const uint8_t *psrc = (const uint8_t *)src;

    if (src > dest) {
        for (size_t i = 0; i < n; i++) {
            pdest[i] = psrc[i];
        }
    } else if (src < dest) {
        for (size_t i = n; i > 0; i--) {
            pdest[i - 1] = psrc[i - 1];
        }
    }

    return dest;
}

int memcmp(const void *s1, const void *s2, size_t n) {
    const uint8_t *p1 = s1;
    const uint8_t *p2 = s2;

    for (size_t i = 0; i < n; i++, p1++, p2++) {
        if (*p1 != *p2) {
            return (*p1 - *p2);
        }
    }

    return 0;
}

size_t strlen(const char *s) {
    size_t ret = 0;
    while (*s != '\0') {
        ret++;
        s++;
    }
    return ret;
}

int strcmp(const char *s1, const char *s2) {
    for (size_t i = 0; i < strlen(s1); i++) {
        if (s1[i] != s2[i]) {
            return s1[i] < s2[i] ? -1 : 1;
        }
    }
    return 0;
}

int strncmp(const char *s1, const char *s2, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (s1[i] != s2[i]) {
            return s1[i] < s2[i] ? -1 : 1;
        }
    }
    return 0;
}

char *strstr(const char *s1, const char *s2) {
    char *orig_s2 = (char *)s2;
    if (*s2 == '\0') {
        return (char *)s1;
    }
    while (*s1 != '\0') {
        if (*s1 == *s2) {
            while (*s2 != '\0') {
                if (*s1 != *s2) {
                    break;
                }
                s1++;
                s2++;
            }
            if (*s2 == '\0') {
                return (char *)s1;
            }
            s2 = orig_s2;
        }
        s1++;
    }
    return NULL;
}

void *memchr(const void *str, int c, size_t n) {
    const unsigned char *p = str;
    for (size_t i = 0; i < n; i++) {
        if (p[i] == (unsigned char)c) {
            return (void *)(p + i);
        }
    }
    return NULL;
}

char *strncpy(char *dest, const char *src, size_t n) {
    size_t i;

    for (i = 0; i < n && src[i] != '\0'; i++) {
        dest[i] = src[i];
    }

    for (; i < n; i++) {
        dest[i] = '\0';
    }

    return dest;
}

char *strdup(const char *s) {
    size_t len = 0;

    // Calculate the length of the string
    while (s[len] != '\0') {
        len++;
    }

    // Allocate memory for the copy (+1 for null terminator)
    char *copy = (char *)kmalloc(len + 1);
    if (!copy) {
        return NULL; // Handle memory allocation failure
    }

    // Copy the string
    for (size_t i = 0; i <= len; i++) {
        copy[i] = s[i];
    }

    return copy;
}

char *strtok(char *str, const char *delim) {
    static char *next = NULL; // Stores position of the next token
    if (str) {
        next = str; // Initialize with the input string
    }
    if (!next) {
        return NULL; // No more tokens
    }

    // Skip leading delimiters
    while (*next && strchr(delim, *next)) {
        next++;
    }
    if (*next == '\0') {
        return NULL; // Reached the end
    }

    char *token_start = next; // Start of token

    // Find the next delimiter
    while (*next && !strchr(delim, *next)) {
        next++;
    }

    if (*next) {
        *next = '\0'; // Null-terminate the token
        next++;       // Move to the next character
    } else {
        next = NULL; // No more tokens
    }

    return token_start;
}

char *strchr(const char *str, int c) {
    while (*str) {
        if (*str == (char)c) {
            return (char *)str; // Return pointer to first occurrence
        }
        str++;
    }
    return (c == '\0') ? (char *)str : NULL; // Handle null terminator case
}

char *strrchr(const char *s, int c) {
    const char *last = NULL;

    while (*s) {
        if (*s == (char)c) {
            last = s;
        }
        s++;
    }

    return (char *)last;
}

char *strtok_r(char *str, const char *delim, char **saveptr) {
    char *token_start;

    // If str is NULL, continue from last position
    if (str == NULL) {
        str = *saveptr;
    }

    // Skip leading delimiters
    while (*str != '\0') {
        const char *d = delim;
        int is_delim  = 0;

        while (*d != '\0') {
            if (*str == *d) {
                is_delim = 1;
                break;
            }
            d++;
        }

        if (!is_delim) {
            break;
        }

        str++;
    }

    // Check if we reached the end
    if (*str == '\0') {
        *saveptr = str;
        return NULL;
    }

    // Mark the start of the token
    token_start = str;

    // Find the end of the token
    while (*str != '\0') {
        const char *d = delim;
        int is_delim  = 0;

        while (*d != '\0') {
            if (*str == *d) {
                is_delim = 1;
                break;
            }
            d++;
        }

        if (is_delim) {
            *str     = '\0';
            *saveptr = str + 1;
            return token_start;
        }

        str++;
    }

    // End of string reached
    *saveptr = str;
    return token_start;
}

void strcpy(char dest[], const char source[]) {
    int i = 0;
    while (1) {
        dest[i] = source[i];

        if (dest[i] == '\0') {
            break;
        }

        i++;
    }
}
