#include "autoconf.h"
#include <stdbool.h>
#include <stddef.h>
#include <system/karg.h>

static karg_t options[CONFIG_KERNEL_INIT_PROC_MAX_ARGS];
static size_t option_count = 0;

int cmdline_init_argc = 0;
char *cmdline_init_argv[CONFIG_KERNEL_INIT_PROC_MAX_ARGS];

static int is_space(char c)
{
    return c == ' ' || c == '\t';
}

static char to_lower(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c + 32;
    return c;
}

static int str_eq_norm(const char *a, const char *b)
{
    while (*a && *b) {
        char ca = *a++;
        char cb = *b++;

        if (ca == '-') ca = '_';
        if (cb == '-') cb = '_';

        if (to_lower(ca) != to_lower(cb))
            return 0;
    }
    return *a == 0 && *b == 0;
}

static int str_eq_ci(const char *a, const char *b)
{
    while (*a && *b) {
        if (to_lower(*a++) != to_lower(*b++))
            return 0;
    }
    return *a == 0 && *b == 0;
}

static int parse_bool(const char *v, bool *out) {
    if (!v) {
        *out = true;
        return 0;
    }

    if (str_eq_ci(v, "1") ||
        str_eq_ci(v, "true") ||
        str_eq_ci(v, "yes") ||
        str_eq_ci(v, "y")) {
        *out = true;
        return 0;
    }

    if (str_eq_ci(v, "0") ||
        str_eq_ci(v, "false") ||
        str_eq_ci(v, "no") ||
        str_eq_ci(v, "n")) {
        *out = false;
        return 0;
    }

    return -1;
}

static char *parse_token(char **p)
{
    char *start;
    char *out;

    while (is_space(**p))
        (*p)++;

    if (**p == 0)
        return 0;

    if (**p == '"') {
        (*p)++;
        start = *p;
        out = start;

        while (**p && **p != '"')
            (*p)++;

        if (**p == '"')
            *(*p)++ = 0;
    } else {
        start = *p;
        out = start;

        while (**p && !is_space(**p))
            (*p)++;

        if (**p)
            *(*p)++ = 0;
    }

    return out;
}

void karg_register(const char *name, karg_cb_t cb, int is_bool)
{
    if (option_count >= CONFIG_KERNEL_CMDLINE_MAX_OPS)
        return;

    options[option_count].name = name;
    options[option_count].callback = cb;
    options[option_count].is_bool = is_bool ? 1 : 0;
    option_count++;
}

void karg_parse(char *cmdline) {
    char *p = cmdline;

    while (is_space(*p))
        p++;

    while (*p) {
        if (*p == '-' && (p[1] == 0 || is_space(p[1]))) {
            p++;
            break;
        }

        char *tok = parse_token(&p);
        if (!tok || !*tok)
            continue;

        char *eq = 0;
        for (char *c = tok; *c; c++) {
            if (*c == '=') {
                eq = c;
                break;
            }
        }

        char *key = tok;
        char *val = 0;

        if (eq) {
            *eq = 0;
            val = eq + 1;
        }

        for (size_t i = 0; i < option_count; i++) {
            if (!str_eq_norm(key, options[i].name))
                continue;

            if (options[i].is_bool) {
                bool b;
                if (parse_bool(val, &b) == 0)
                    options[i].callback(b ? "1" : "0");
            } else {
                options[i].callback(val);
            }

            break;
        }
    }

    while (*p && cmdline_init_argc < CONFIG_KERNEL_INIT_PROC_MAX_ARGS) {
        char *arg = parse_token(&p);
        if (arg)
            cmdline_init_argv[cmdline_init_argc++] = arg;
    }
}
