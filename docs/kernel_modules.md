# PurpleK2 Kernel Module System

Kernel Modules are an essential part of every Kernel / Operating System providing drivers and functionality in early stages. In this doc i will describe the approach PurpleK2 uses to load its Kernel Module files (.km)

## What are .km files
.km (Kernel Module) files are Dynamic Linked ELFs, linked against kernel symbols (like write, open, printf, etc...) where the kernel resolves these relocations. There are two important driver functions: `driver_entry`, which is called when the module is started and `driver_exit` which is called when the module is well terminated.