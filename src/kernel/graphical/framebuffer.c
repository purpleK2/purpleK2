#include "framebuffer.h"

#include <kernel.h>
#include <limine.h>

#include <stdint.h>

void drawPixel(uint32_t x, uint32_t y, uint32_t r, uint32_t g, uint32_t b) {
    struct limine_framebuffer *framebuffer_86 =
        get_bootloader_data()->framebuffer;
    if (!framebuffer_86 || !framebuffer_86->address ||
        x >= framebuffer_86->width || y >= framebuffer_86->height)
        return;

    uint32_t color = (r << framebuffer_86->red_mask_shift) |
                     (g << framebuffer_86->green_mask_shift) |
                     (b << framebuffer_86->blue_mask_shift);
    uint32_t *fb = (uint32_t *)framebuffer_86->address;
    fb[y * (framebuffer_86->pitch / 4) + x] = color;
}
