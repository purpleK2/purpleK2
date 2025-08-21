#ifndef TGA_H
#define TGA_H 1

#include <stddef.h>
#include <stdint.h>

#include <limine.h>

#include <util/macro.h>

typedef struct tga_header {
    uint8_t iid_len;
    uint8_t cmap_type;
    uint8_t image_type;

    // color map spec
    uint16_t cmap_firstentry; // index of first color map entry that is included
                              // in the file
    uint16_t cmap_entries;    // number of entries of the color map that are
                              // included in the file
    uint8_t cmap_entrybits;   // number of bits per color map entry

    // image spec
    uint16_t x_origin;
    uint16_t y_origin;
    uint16_t width;
    uint16_t height;
    uint8_t bpp;
    uint8_t image_descriptor;

    /*
        Next fields:
        - Image ID (length: iid_len)
        - Color map (length: cmap_len)

        - Image data
    */

} PACKED tgaheader_t;

// no footer >:))

typedef enum tga_colormap_type {
    TGA_NOCMAP   = 0,
    TGA_CMAP     = 1,
    TGA_CMAP_DEV = 128, // until 255
} tga_cmaptype_t;

typedef enum tga_image_type {
    TGA_NOIDATA = 0,
    TGA_COMA    = 1, // COlor MAp
    TGA_TRCO    = 2, // TRue COlor
    TGA_GRAY    = 3, // GRAYscale
} tga_itype_t;

#define TGA_ITYPE_RLE (1 << 4)

#define TGA_IDESC_RTL (1 << 4)
#define TGA_IDESC_TTB (1 << 5)

#define TGA_ALPHADEPTH(d) (d & 0b111)

void load_tga_to_framebuffer(const char *filename);

void tga_putcolor32_8(tgaheader_t *tga, uint32_t *cmap, uint8_t *image);

#endif