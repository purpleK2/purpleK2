#include "stdio.h"

#include <io.h>
#include <limine.h>
#include <spinlock.h>
#include <stdarg.h>
#include <terminal/terminal.h>
#include <util/va_list.h>

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

lock_t STDIO_FB_LOCK;
lock_t STDIO_E9_LOCK;

uint32_t current_bg;
uint32_t current_fg;

// unlocks spinlocks by force
// interrupts are disabled to avoid other ones to be fired
void stdio_panic_init() {
    asm("cli");

    spinlock_release(&STDIO_FB_LOCK);
    spinlock_release(&STDIO_E9_LOCK);
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

void putc(char c) {
    _term_putc(c);
}

void dputc(char c) {
    _outb(0xE9, c);
}

void bsod_init() {
    set_screen_bg_fg(PANIC_BG, DEFAULT_FG);

    clearscreen();
}

void kprintf_impl(const char *buffer, int len) {
    spinlock_acquire(&STDIO_FB_LOCK);

    for (int i = 0; i < len; ++i) {
        putc(buffer[i]);
    }

    spinlock_release(&STDIO_FB_LOCK);
}

void debugf_impl(const char *buffer, int len) {
    spinlock_acquire(&STDIO_E9_LOCK);

    for (int i = 0; i < len; ++i) {
        dputc(buffer[i]);
    }

    spinlock_release(&STDIO_E9_LOCK);
}

void mprintf_impl(const char *buffer, int len) {
    debugf_impl(buffer, len);
    kprintf_impl(buffer, len);
}

int printf(void (*putc_function)(const char *, int), const char *fmt, ...) {
    char buffer[1024];
    va_list args;

    va_start(args, fmt);
    int length = npf_vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    if (length < 0 || length >= (int)sizeof(buffer)) {
        return -1;
    }

    (*putc_function)(buffer, length);

    return length;
}
