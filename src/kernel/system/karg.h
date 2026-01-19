#ifndef KARG_H
#define KARG_H

#include <autoconf.h>

#include <stdbool.h>
typedef int (*karg_cb_t)(const char *value);

typedef struct karg {
    const char *name;
    karg_cb_t callback;
    bool is_bool;
} karg_t;

extern int   cmdline_init_argc;
extern char *cmdline_init_argv[CONFIG_KERNEL_INIT_PROC_MAX_ARGS];

void karg_register(const char *name, karg_cb_t cb, int is_bool);
void karg_parse(char *cmdline);

#endif // KARG_H