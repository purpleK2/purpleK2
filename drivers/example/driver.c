#include <stdio.h>

#include <module/modinfo.h>

__attribute__((section(".modinfo")))
const modinfo_t example_module_modinfo = {.name = "example_module"};

void module_exit() {
    kprintf("Going under!");
}

void module_entry() {
    kprintf("Hello from the example kernel module");

    module_exit();
}