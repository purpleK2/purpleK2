#include "stdio.h"

#include <io.h>
#include <limine.h>
#include <stdarg.h>
#include <terminal/terminal.h>
#include <util/va_list.h>

#include <spinlock.h>

#define NANOPRINTF_USE_FIELD_WIDTH_FORMAT_SPECIFIERS     1
#define NANOPRINTF_USE_PRECISION_FORMAT_SPECIFIERS       1
#define NANOPRINTF_USE_FLOAT_FORMAT_SPECIFIERS           0
#define NANOPRINTF_USE_SMALL_FORMAT_SPECIFIERS           1
#define NANOPRINTF_USE_LARGE_FORMAT_SPECIFIERS           1
#define NANOPRINTF_USE_BINARY_FORMAT_SPECIFIERS          1
#define NANOPRINTF_USE_WRITEBACK_FORMAT_SPECIFIERS       0
#define NANOPRINTF_SNPRINTF_SAFE_TRIM_STRING_ON_OVERFLOW 1
typedef long ssize_t;

#define NANOPRINTF_IMPLEMENTATION
#include <nanoprintf.h>

uint32_t current_bg;
uint32_t current_fg;

atomic_flag STDIO_FB_LOCK = ATOMIC_FLAG_INIT;
atomic_flag STDIO_E9_LOCK = ATOMIC_FLAG_INIT;

// yeah, it's a bit brutal :P
void stdio_force_unlock() {
    spinlock_release(&STDIO_FB_LOCK);
    spinlock_release(&STDIO_E9_LOCK);
}

// unlocks spinlocks by force
// interrupts are disabled to avoid other ones to be fired
void stdio_panic_init() {
    asm("cli");

    stdio_force_unlock();
}

uint32_t fb_get_bg() {
    return current_bg;
}

uint32_t fb_get_fg() {
    return current_fg;
}

void fb_set_bg(uint32_t bg_rgb) {
    current_bg = bg_rgb;
    _term_set_bg(bg_rgb);
}

void fb_set_fg(uint32_t fg_rgb) {
    current_fg = fg_rgb;
    _term_set_fg(fg_rgb);
}

void set_screen_bg_fg(uint32_t bg_rgb, uint32_t fg_rgb) {
    fb_set_bg(bg_rgb);
    fb_set_fg(fg_rgb);
}

void clearscreen() {
    _term_cls();
}

void putc(int c, void *ctx) {
    UNUSED(ctx);
    _term_putc(c);
}

void dputc(int c, void *ctx) {
    UNUSED(ctx);
    _outb(0xE9, c);
}

void mputc(int c, void *ctx) {
    putc(c, ctx);
    dputc(c, ctx);
}

void bsod_init() {
    set_screen_bg_fg(PANIC_BG, DEFAULT_FG);

    clearscreen();
}

int printf(void (*putc_function)(int, void *), const char *fmt, va_list var) {
    return npf_vpprintf(putc_function, NULL, fmt, var);
}

int kprintf(const char *fmt, ...) {
    va_list args;

    va_start(args, fmt);
    spinlock_acquire(&STDIO_FB_LOCK);
    int length = printf(putc, fmt, args);
    spinlock_release(&STDIO_FB_LOCK);
    va_end(args);

    return length;
}

int debugf(const char *fmt, ...) {
    va_list args;

    va_start(args, fmt);
    spinlock_acquire(&STDIO_E9_LOCK);
    int length = printf(dputc, fmt, args);
    spinlock_release(&STDIO_E9_LOCK);
    va_end(args);

    return length;
}

int mprintf(const char *fmt, ...) {
    va_list args;

    va_start(args, fmt);

    spinlock_acquire(&STDIO_FB_LOCK);
    int length = printf(putc, fmt, args);
    spinlock_release(&STDIO_FB_LOCK);

    spinlock_acquire(&STDIO_E9_LOCK);
    length += printf(dputc, fmt, args);
    spinlock_release(&STDIO_E9_LOCK);

    va_end(args);

    return length;
}
