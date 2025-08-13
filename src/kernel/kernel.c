#include "kernel.h"
#include "dev/display/fb/fbdev.h"
#include "fs/devfs/devfs.h"

#include <autoconf.h>

#include <arch.h>
#include <cpu.h>
#include <io.h>
#include <limine.h>

#include <acpi/acpi.h>
#include <ahci/ahci.h>

#include <dev/device.h>
#include <dev/fs/initrd.h>
#include <dev/port/e9/e9.h>
#include <dev/port/parallel/parallel.h>
#include <dev/port/serial/serial.h>
#include <dev/std/helper.h>

#include <fs/cpio/newc.h>
#include <fs/file_io.h>
#include <fs/ramfs/ramfs.h>
#include <fs/vfs/vfs.h>

#include <memory/heap/kheap.h>
#include <memory/pmm/pmm.h>
#include <memory/vmm/vflags.h>
#include <memory/vmm/vma.h>
#include <memory/vmm/vmm.h>
#include <paging/paging.h>

#include <pci/pci.h>
#include <pcie/pcie.h>

#include <scheduler/scheduler.h>

#include <smp/ipi.h>
#include <smp/smp.h>

#include <tables/hpet.h>

#include <terminal/psf.h>
#include <terminal/terminal.h>

#include <tsc/tsc.h>

#include <util/assert.h>
#include <util/macro.h>

#include <test.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define INITRD_FILE "initrd.cpio"
#define INITRD_PATH "/" INITRD_FILE

USED SECTION(".requests") static volatile LIMINE_BASE_REVISION(3);

USED SECTION(".requests") static volatile struct limine_framebuffer_request
    framebuffer_request = {.id = LIMINE_FRAMEBUFFER_REQUEST, .revision = 0};

USED SECTION(".requests") static volatile struct limine_memmap_request
    memmap_request = {.id = LIMINE_MEMMAP_REQUEST, .revision = 0};

USED SECTION(".requests") static volatile struct limine_paging_mode_request
    paging_mode_request = {.id = LIMINE_PAGING_MODE_REQUEST, .revision = 0};

USED SECTION(".requests") static volatile struct limine_hhdm_request
    hhdm_request = {.id = LIMINE_HHDM_REQUEST, .revision = 0};

USED SECTION(".requests") static volatile struct limine_kernel_address_request
    kernel_address_request = {.id       = LIMINE_KERNEL_ADDRESS_REQUEST,
                              .revision = 0};

USED SECTION(".requests") static volatile struct limine_rsdp_request
    rsdp_request = {.id = LIMINE_RSDP_REQUEST, .revision = 0};

USED SECTION(".requests") static volatile struct limine_module_request
    module_request = {.id = LIMINE_MODULE_REQUEST, .revision = 0};

USED SECTION(".requests") static volatile struct limine_firmware_type_request
    firmware_type_request = {.id = LIMINE_FIRMWARE_TYPE_REQUEST, .revision = 0};

USED SECTION(".requests") static volatile struct limine_smp_request
    smp_request = {.id = LIMINE_SMP_REQUEST, .revision = 0};

USED SECTION(".requests") static volatile struct limine_kernel_file_request
    kernel_file_request = {.id = LIMINE_KERNEL_FILE_REQUEST, .revision = 0};

USED SECTION(
    ".requests_start_marker") static volatile LIMINE_REQUESTS_START_MARKER;

USED SECTION(".requests_end_marker") static volatile LIMINE_REQUESTS_END_MARKER;

struct limine_framebuffer *framebuffer;
struct limine_memmap_response *memmap_response;
struct limine_memmap_entry *memmap_entry;
struct limine_hhdm_response *hhdm_response;
struct limine_kernel_address_response *kernel_address_response;
struct limine_paging_mode_response *paging_mode_response;
struct limine_rsdp_response *rsdp_response;
struct limine_module_response *module_response;
struct limine_file *kernel_file;

struct bootloader_data limine_parsed_data;

struct bootloader_data *get_bootloader_data() {
    return &limine_parsed_data;
    get_cpu();
}

vmm_context_t *kernel_vmm_ctx;

void cf() {
    debugf("Hello :3\n");
}

// kernel main function
void kstart(void) {
    asm("cli");
    // Ensure the bootloader actually understands our base revision (see spec).
    if (LIMINE_BASE_REVISION_SUPPORTED == false) {
        _hcf();
    }

    // Ensure we got a framebuffer.
    if (framebuffer_request.response == NULL ||
        framebuffer_request.response->framebuffer_count < 1) {
        _hcf();
    }

    // Fetch the first framebuffer.
    framebuffer = framebuffer_request.response->framebuffers[0];
    limine_parsed_data.framebuffer = framebuffer;

    psfLoadDefaults();
    _term_init();

    set_screen_bg_fg(DEFAULT_BG, DEFAULT_FG); // black-ish, white-ish
    clearscreen();

    limine_parsed_data.kernel_file_data =
        kernel_file_request.response->kernel_file->address;
    limine_parsed_data.kernel_file_size =
        kernel_file_request.response->kernel_file->size;

#ifndef CONFIG_ENABLE_64_BIT
    kprintf_panic("Kernel wasn't configured with 64-Bit support!\n");
    _hcf(); // hcf also works on 32-Bit
#endif

    arch_base_init();

    uint64_t system_startup_time;
    mark_time(&system_startup_time);
    system_startup_time -=
        1000; // add one second because of the TSC calibration

    char *FIRMWARE_TYPE;

    if (firmware_type_request.response != NULL) {
        uint64_t firmware_type = firmware_type_request.response->firmware_type;
        switch (firmware_type) {
        case LIMINE_FIRMWARE_TYPE_X86BIOS:
            FIRMWARE_TYPE = "X86BIOS";
            break;

        case LIMINE_FIRMWARE_TYPE_UEFI32:
            FIRMWARE_TYPE = "UEFI32";
            break;

        case LIMINE_FIRMWARE_TYPE_UEFI64:
            FIRMWARE_TYPE = "UEFI64";
            break;

        default:
            FIRMWARE_TYPE = "No firmware type found!";
            break;
        }
    } else {
        FIRMWARE_TYPE = "No firmware type found!";
    }

    debugf_debug("%s\n", FIRMWARE_TYPE);

    debugf_debug("Current video mode is: %dx%d address: %p\n\n",
                 framebuffer->width, framebuffer->height, framebuffer->address);

    if (kernel_address_request.response == NULL) {
        kprintf_panic("Couldn't get kernel address!\n");
        _hcf();
    }
    kernel_address_response = kernel_address_request.response;
    limine_parsed_data.kernel_base_physical =
        kernel_address_response->physical_base;
    limine_parsed_data.kernel_base_virtual =
        kernel_address_response->virtual_base;
    debugf_debug("Kernel address: (phys)%llx (virt)%llx\n\n",
                 limine_parsed_data.kernel_base_physical,
                 limine_parsed_data.kernel_base_virtual);

    debugf_debug("Kernel sections:\n");
    debugf_debug("\tkernel_start: %p\n", &__kernel_start);
    debugf_debug("\tkernel_text_start: %p; kernel_text_end: %p\n",
                 &__kernel_text_start, &__kernel_text_end);
    debugf_debug("\tkernel_rodata_start: %p; kernel_rodata_end: %p\n",
                 &__kernel_rodata_start, &__kernel_rodata_end);
    debugf_debug("\tkernel_data_start: %p; kernel_data_end: %p\n",
                 &__kernel_data_start, &__kernel_data_end);
    debugf_debug("\tlimine_requests_start: %p; limine_requests_end: %p\n",
                 &__limine_reqs_start, &__limine_reqs_end);
    debugf_debug("\tkernel_end: %p\n", &__kernel_end);

    if (memmap_request.response == NULL ||
        memmap_request.response->entry_count < 1) {
        debugf_panic("No memory map received!\n");
        _hcf();
    }

    memmap_response = memmap_request.response;

    limine_parsed_data.limine_memory_map  = memmap_response->entries;
    limine_parsed_data.memmap_entry_count = memmap_response->entry_count;

    // Load limine's memory map into OUR struct
    limine_parsed_data.usable_entry_count = 0;
    for (uint64_t i = 0; i < limine_parsed_data.memmap_entry_count; i++) {
        memmap_entry = limine_parsed_data.limine_memory_map[i];

        if (memmap_entry->type == LIMINE_MEMMAP_USABLE) {
            limine_parsed_data.memory_usable_total += memmap_entry->length;
            limine_parsed_data.usable_entry_count++;
        }

        debugf_debug(
            "Entry n. %lld; Region start: %llx; length: %llx; type: %s\n", i,
            memmap_entry->base, memmap_entry->length,
            memory_block_type[memmap_entry->type]);
    }

    limine_parsed_data.memory_total =
        limine_parsed_data
            .limine_memory_map[limine_parsed_data.memmap_entry_count - 1]
            ->base +
        limine_parsed_data
            .limine_memory_map[limine_parsed_data.memmap_entry_count - 1]
            ->length -
        limine_parsed_data
            .limine_memory_map[limine_parsed_data.memmap_entry_count - 1]
            ->length;

    if (hhdm_request.response == NULL) {
        debugf_panic("Couldn't get Higher Half Direct Map Offset!\n");
        _hcf();
    }

    hhdm_response = hhdm_request.response;

    limine_parsed_data.hhdm_offset = hhdm_response->offset;
    debugf_debug("Higher Half Direct Map offset: %llx\n",
                 limine_parsed_data.hhdm_offset);

    pmm_init();
    kprintf_ok("Initialized PMM\n");

    if (paging_mode_request.response == NULL) {
        kprintf_panic("We've got no paging!\n");
        _hcf();
    }
    paging_mode_response = paging_mode_request.response;

    if (paging_mode_response->mode < paging_mode_request.min_mode ||
        paging_mode_response->mode > paging_mode_request.max_mode) {
        kprintf_panic("%lluth paging mode is not supported!\n",
                      paging_mode_response->mode);
        _hcf();
    }
    debugf_debug("%lluth level paging is available\n",
                 4 + paging_mode_response->mode);

    if (!check_pae()) {
        debugf_debug("PAE is not available\n");
    } else {
        debugf_debug("PAE is available\n");
    }

    debugf_debug("Initializing paging\n");
    // kernel PML4 table
    uint64_t *kernel_pml4 = (uint64_t *)pmm_alloc_page();
    paging_init((uint64_t *)PHYS_TO_VIRTUAL(kernel_pml4));

    kernel_vmm_ctx = vmm_ctx_init(kernel_pml4, VMO_KERNEL_RW);
    vmm_init(kernel_vmm_ctx);
    vmm_switch_ctx(kernel_vmm_ctx);
    kprintf_ok("Initialized VMM\n");

    kmalloc_init();

    debugf_debug("Malloc Test:\n");
    void *ptr1 = kmalloc(0xA0);
    debugf_debug("[1] kmalloc(0xA0) @ %p\n", ptr1);
    void *ptr2 = kmalloc(0xA3B0);
    debugf_debug("[2] kmalloc(0xA3B0) @ %p\n", ptr2);
    kfree(ptr1);
    kfree(ptr2);
    ptr1 = kmalloc(0xF00);
    debugf_debug("[3] kmalloc(0xF00) @ %p\n", ptr1);
    kfree(ptr1);
    kprintf_ok("kheap init done\n");

    if (rsdp_request.response == NULL) {
        kprintf_panic("Couldn't get RSDP address!\n");
        _hcf();
    }
    rsdp_response                         = rsdp_request.response;
    limine_parsed_data.rsdp_table_address = (uint64_t *)rsdp_response->address;
    debugf_debug("Address of RSDP: %p\n",
                 limine_parsed_data.rsdp_table_address);

    if (uacpi_init() == 0) {
        kprintf_ok("uACPI initialized successfully!!\n");
    } else {
        kprintf_panic("Some errors occured during uACPI initialization.");
        debugf_panic(
            "Some errors occured during uACPI initialization. Halting...\n");

        _hcf();
    }

#if defined(__x86_64__)
#ifdef CONFIG_ENABLE_APIC
#include <apic/ioapic/ioapic.h>
#include <apic/lapic/lapic.h>
#include <interrupts/irq.h>

    if (check_apic()) {
        asm("cli");
        debugf_debug("APIC is supported\n");

        lapic_init();
        ioapic_init();

        kprintf_ok("LAPIC + IOAPIC init done\n");
        asm("sti");
    } else {
        debugf_debug("APIC is not supported. Going on with legacy PIC\n");
    }

#endif
#endif

    hpet_init();
    kprintf_ok("HPET initialized\n");

    char *cpu_name   = kmalloc(49);
    char *cpu_vendor = kmalloc(13);
    get_cpu_name(cpu_name);
    get_cpu_vendor(cpu_vendor);
    kprintf("CPU: %s %s @ %llu MHz\n", cpu_vendor, cpu_name,
            tsc_frequency / 1000 / 1000);
    kfree(cpu_vendor);
    kfree(cpu_name);

    // hypervisor
    if (check_hypervisor()) {
        char hv[13];
        if (get_hypervisor(hv) == 0) {
            kprintf("Running on hypervisor: %s\n\n", hv);
        }
    }

    kprintf("Total Memory: 0x%llx (%lu MBytes)\n",
            limine_parsed_data.memory_total,
            limine_parsed_data.memory_total / 0x100000);

    kprintf("Total available Memory: 0x%llx (%lu MBytes)\n\n",
            limine_parsed_data.memory_usable_total,
            limine_parsed_data.memory_usable_total / 0x100000);

    if (!module_request.response) {
        kprintf_warn("No modules loaded.\n");
    }

    module_response = module_request.response;

    struct limine_file *initrd = NULL;

    for (uint64_t module = 0; module < module_response->module_count;
         module++) {
        struct limine_file *limine_module = module_response->modules[module];
        kprintf_info("Module %s loaded\n", limine_module->path);

        if (strcmp(INITRD_PATH, limine_module->path) == 0) {
            kprintf_ok("Found initrd image\n");
            initrd = limine_module;
        }
    }

    if (!initrd) {
        kprintf_panic("No initrd.cpio file found.");
        _hcf();
    }

    kprintf_info("Initrd loaded at address %p\n", initrd->address);

    cpio_fs_t fs;
    memset(&fs, 0, sizeof(cpio_fs_t));

    int ret = cpio_fs_parse(&fs, initrd->address, initrd->size);
    if (ret < 0) {
        kprintf_panic("Failed to parse initrd.cpio file.");
        _hcf();
    }

    kprintf_ok("Initrd.cpio parsed successfully!\n");

    // test CPIO read
    char buffer[256];
    size_t read_size = cpio_fs_read(&fs, "test.txt", buffer, sizeof(buffer));
    if (read_size > 0) {
        kprintf("Read %zu bytes from test.txt:\n%.*s\n\n", read_size,
                (int)read_size, buffer);
    } else {
        kprintf_warn("Failed to read test.txt from initrd.cpio\n");
    }

    // create the RAMFS
    ramfs_t *cpio_ramfs = ramfs_create();
    if (cpio_ramfs_init(&fs, cpio_ramfs) != 0) {
        kprintf_warn("CPIO to RAMFS conversion failed!\n");
    } else {
        kprintf("/\n", "NAME", "SIZE");
        ramfs_print(cpio_ramfs->root_node, 0);
        kprintf_ok("CPIO to RAMFS conversion done\n");
    }

    // create the VFS for CPIO
    ramfs_vfs_init(cpio_ramfs, "/cpio");

    fileio_t *test_file = open("/cpio/directory/another.txt", 0);
    if (!test_file) {
        kprintf_warn("Couldn't open file!\n");
    }

    sprintf(buffer, "BTW this is not the original file content LOLLL\n");
    write(test_file, buffer, strlen(buffer));

    seek(test_file, 0, SEEK_SET); // go back to start of file

    read(test_file, sizeof(buffer), buffer);
    kprintf("VFS read test: %s", buffer);

    if (close(test_file) == EOK) {
        kprintf_ok("File operations completed successfully!\n");
    }

    register_std_devices();
    dev_initrd_init(initrd->address);
    dev_e9_init();
    dev_serial_init();
    dev_parallel_init();
    dev_fb_init();

#ifdef CONFIG_DEVFS_ENABLE
    devfs_t *devfs = devfs_create();
    if (devfs_vfs_init(devfs, "/dev") != EOK) {
        kprintf_warn("Failed to initialize DEVFS!\n");
    } else {
        kprintf_ok("DEVFS initialized successfully!\n");
    }

    devfs_print(devfs->root_node, 0);

#endif

    limine_parsed_data.cpu_count = smp_request.response->cpu_count;
    limine_parsed_data.cpus      = smp_request.response->cpus;

    // smp_init();
    // limine_parsed_data.smp_enabled = true;

    cpio_file_t *pci_ids = cpio_fs_get_file(&fs, "pci.ids");

    pci_scan(pci_ids);
    pci_print_list();
    kprintf_ok("PCI devices parsing done\n");
    if (pcie_devices_init(pci_ids) != 0) {
        kprintf_warn("Failed to parse PCIe devices!\n");
    } else {
        kprintf_ok("PCIe devices parsing done\n");
    }

    limine_parsed_data.boot_time = get_ms(system_startup_time);

    kprintf("System started: Time took: %llu seconds %llu ms.\n",
            limine_parsed_data.boot_time / 1000,
            limine_parsed_data.boot_time % 1000);

    init_scheduler(cf);
    irq_registerHandler(0, scheduler_timer_tick);

    struct limine_framebuffer *fb =
        (struct limine_framebuffer *)get_device("fb0")->data;
    load_bmp_to_framebuffer("/cpio/spamtong.bmp", fb);

    kprintf("Ha bet you didnt see that [[BIG SHOT]]!\n");

    for (;;)
        ;
}
