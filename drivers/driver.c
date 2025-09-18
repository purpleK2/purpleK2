#include <stdio.h>

#include <module/modinfo.h>

const modinfo_t example_module_modinfo = {.name = "example_module"};

void module_exit() {
    debugf("Going under!");
}

void module_entry() {
    debugf("Hello from the example kernel module");

    module_exit();
}