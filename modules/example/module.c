#include <stdio.h>

#include <module/modinfo.h>

const modinfo_t example_module_modinfo = {.name = "example_module"};

void module_exit() {
    kprintf("Example Module exiting!\n");
}

void module_entry() {
    kprintf("Hello from the example kernel module!\n");

    module_exit();
}