#include <stdio.h>

#include <module/modinfo.h>

const modinfo_t modinfo = {.name        = "example_module",
                           .version     = "1.0.0",
                           .author      = "NotNekodev",
                           .description = "Example Module",
                           .license     = "MIT",
                           .url      = "https://github.com/purplek2/PurpleK2",
                           .priority = MOD_PRIO_LOW,
                           .deps = {"kernel", NULL}}; // terminated with a \0

void module_exit() {
    kprintf("Example Module exiting!\n");
}

void module_entry() {
    kprintf("Hello from the example kernel module!\n");

    module_exit();
}