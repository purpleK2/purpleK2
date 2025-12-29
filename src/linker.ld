/* Tell the linker that we want an x86_64 ELF64 output file */
OUTPUT_FORMAT(elf64-x86-64)

/* We want the symbol kmain to be our entry point */
ENTRY(kstart)

/* Define the program headers we want so the bootloader gives us the right */
/* MMU permissions */
PHDRS
{
    text    PT_LOAD    FLAGS((1 << 0) | (1 << 2)) ; /* Execute + Read */
    rodata  PT_LOAD    FLAGS((1 << 2)) ;            /* Read only */
    data    PT_LOAD    FLAGS((1 << 1) | (1 << 2)) ; /* Write + Read */
    dynamic PT_DYNAMIC FLAGS((1 << 1) | (1 << 2)) ; /* Dynamic PHDR for relocations */
}

SECTIONS
{
    /* We want to be placed in the topmost 2GiB of the address space, for optimisations */
    /* and because that is what the Limine spec mandates. */
    /* Any address in this region will do, but often 0xffffffff80000000 is chosen as */
    /* that is the beginning of the region. */
    . = 0xffffffff80000000;

    /* Kernel and text section start */
    __kernel_start = .;

    .text BLOCK(4K) : ALIGN(CONSTANT(MAXPAGESIZE))
    {
        __kernel_text_start = .;
        *(.text .text.*)
        __kernel_text_end = .;    /* Kernel text section end */
    } :text

    .rodata BLOCK(4K) : ALIGN(CONSTANT(MAXPAGESIZE))
    {
        __kernel_rodata_start = .;
        *(.rodata .rodata.*)
        __kernel_rodata_end = .;
    } :rodata

    .data BLOCK(4K) : ALIGN(CONSTANT(MAXPAGESIZE))
    {
        __kernel_data_start = .;  /* Kernel data section start */
        *(.data .data.*)

        __limine_reqs_start = .;
        /* Place the sections that contain the Limine requests as part of the .data */
        /* output section. */
        KEEP(*(.requests_start_marker))
        KEEP(*(.requests))
        KEEP(*(.requests_end_marker))
        __limine_reqs_end = .;

    } :data

    /* Dynamic section for relocations, both in its own PHDR and inside data PHDR */
    .dynamic : ALIGN(CONSTANT(MAXPAGESIZE)) {
        *(.dynamic)
    } :data :dynamic
    __kernel_data_end = .;    /* Kernel data section end */

    /* NOTE: .bss needs to be the last thing mapped to :data, otherwise lots of */
    /* unnecessary zeros will be written to the binary. */
    /* If you need, for example, .init_array and .fini_array, those should be placed */
    /* above this. */
    .bss :
    {
        *(.bss .bss.*)
        *(COMMON)
    } :data


    /* Discard .note.* and .eh_frame* since they may cause issues on some hosts. */
    /DISCARD/ :
    {
        *(.eh_frame*)
        *(.note .note.*)
    }

    __kernel_end = .;         /* Kernel section end */
}
