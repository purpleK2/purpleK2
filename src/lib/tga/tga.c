#include "tga.h"

#include <memory/heap/kheap.h>

#include <fs/file_io.h>
#include <stdio.h>

#include <graphical/framebuffer.h>

void load_tga_to_framebuffer(const char *filename) {
    fileio_t *tga = open(filename, 0);
    if (!tga) {
        kprintf_warn("Failed to open TGA file!\n");
        return;
    }

    tgaheader_t header;

    read(tga, sizeof(header), &header);

    if (header.iid_len) {
        // TODO: Handle Image ID len
        // if there's something useful in it
    }

    if (header.cmap_type & TGA_ITYPE_RLE) {
        debugf_warn("Idk what run-length encoding is, so i'm not doing "
                    "whatever this is\n");
        return;
    }

    debugf_debug("Image: %hux%hux%hhu\n", header.width, header.height,
                 header.bpp);

    size_t image_size =
        header.width * header.height * (header.bpp / 8); // size in bytes

    void *img_buffer = kmalloc(image_size);

    size_t offset = sizeof(header) + header.iid_len +
                    (header.cmap_entries * (header.cmap_entrybits / 8));
    seek(tga, offset, SEEK_SET);
    read(tga, image_size, img_buffer);

    switch (header.cmap_type) {
    case TGA_COMA:
        // always the size in bytes :3c
        size_t cmap_size = header.cmap_entries * (header.cmap_entrybits / 8);
        void *cmap       = kmalloc(cmap_size);
        offset           = sizeof(header) + header.iid_len;
        seek(tga, offset, SEEK_SET);
        read(tga, cmap_size, cmap);

        // TODO: handle different depths and stuff

        tga_putcolor32_8(&header, cmap, img_buffer);
        break;

    default:
        debugf_warn("Unsupported TGA color map type\n");
        return;
    }

    close(tga);
}

// colourmap TGA, 32 bits RGBA, 8 bit depth
void tga_putcolor32_8(tgaheader_t *tga, uint32_t *cmap, uint8_t *image) {
    for (size_t y = 0; y < tga->height; y++) {
        for (size_t x = 0; x < tga->width; x++) {
            uint8_t idx    = image[(y * tga->width) + x];
            uint32_t color = cmap[idx];

            drawPixel(x, y, ((color >> 16) & 0xFF), ((color >> 8) & 0xFF),
                      ((color & 0xFF)));
        }
    }
}
