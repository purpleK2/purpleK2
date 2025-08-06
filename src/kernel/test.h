#ifndef TEST_H
#define TEST_H 1
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <fs/file_io.h>
#include <stdio.h>

// BMP header structures
#pragma pack(push, 1)
typedef struct {
    uint16_t signature; // 'BM'
    uint32_t file_size;
    uint16_t reserved1;
    uint16_t reserved2;
    uint32_t pixel_offset;
} bmp_file_header_t;

typedef struct {
    uint32_t header_size;
    int32_t width;
    int32_t height;
    uint16_t planes;
    uint16_t bpp;
    uint32_t compression;
    uint32_t image_size;
    int32_t x_ppm;
    int32_t y_ppm;
    uint32_t colors_used;
    uint32_t important_colors;
} bmp_info_header_t;
#pragma pack(pop)

void load_bmp_to_framebuffer(const char *filename,
                             struct limine_framebuffer *fb) {
    fileio_t *bmp_file = open(filename, 0);
    if (!bmp_file) {
        kprintf_warn("Failed to open BMP file!\n");
        return;
    }

    bmp_file_header_t file_header;
    bmp_info_header_t info_header;

    read(bmp_file, sizeof(file_header), &file_header);
    read(bmp_file, sizeof(info_header), &info_header);

    if (file_header.signature != 0x4D42) {
        kprintf_warn("Not a BMP file!\n");
        close(bmp_file);
        return;
    }

    if (info_header.bpp != 24 || info_header.compression != 0) {
        kprintf_warn("Only 24-bit uncompressed BMPs supported!\n");
        close(bmp_file);
        return;
    }

    uint32_t bmp_width  = info_header.width;
    uint32_t bmp_height = info_header.height;
    bool upside_down    = bmp_height > 0;
    if (!upside_down)
        bmp_height = -bmp_height;

    uint32_t pixel_size = fb->bpp / 8;
    uint32_t bmp_row_bytes =
        ((bmp_width * 3 + 3) & ~3); // BMP rows padded to 4 bytes

    uint8_t row_buffer[bmp_row_bytes];

    for (uint32_t y = 0; y < bmp_height; y++) {
        uint32_t bmp_y    = upside_down ? (bmp_height - 1 - y) : y;
        size_t bmp_offset = file_header.pixel_offset + bmp_y * bmp_row_bytes;

        seek(bmp_file, bmp_offset, SEEK_SET);
        read(bmp_file, bmp_row_bytes, row_buffer);

        if (y >= fb->height)
            continue;

        uint8_t *fb_row = (uint8_t *)fb->address + y * fb->pitch;

        for (uint32_t x = 0; x < bmp_width && x < fb->width; x++) {
            uint8_t *src_pixel = &row_buffer[x * 3];
            uint8_t *dst_pixel = &fb_row[x * pixel_size];

            dst_pixel[0] = src_pixel[0]; // B
            dst_pixel[1] = src_pixel[1]; // G
            dst_pixel[2] = src_pixel[2]; // R

            if (pixel_size == 4) {
                dst_pixel[3] = 0xFF; // opaque alpha if 32bpp framebuffer
            }
        }
    }

    close(bmp_file);
}
#endif
