# purpleK2

A freestanding 64-Bit kernel
<image src="assets/banner.png" width=700>

<br>

> [!IMPORTANT]  
> This Kernel is not ready for use yet.

## Table of Contents
- [Why make a Kernel](#why-make-a-kernel)
- [Current Development Status](#current-development-status)
- [The base of the Kernel](#the-base-of-the-kenrel)
- [Building the Kernel](#building-the-kernel)
    - [Testing on real hardware](#testing-on-real-hardware)
    - [Prequisites](#prequisites)
    - [Setting up a cross compiler](#setting-up-a-cross-compiler)
        - [Prebuilt binaries](#prebuilt-binaries)
        - [Built it yourself](#build-it-yourself)
    - [Building the ISO](#building-the-iso)
- [Emulating the Kernel using QEMU](#emulating-the-kernel-using-qemu)
- [Debugging the Kernel using QEMU and GDB](#debugging-the-kernel-using-qemu-and-gdb)
- [Contributing](#contributing)
- [Getting `compile_commands.json`](#getting-compile_commandsjson)
- [License](#license)

## Why make a Kernel
At the beginning of July 2024, after watching some videos about OSDev, I decided to start developing my own 64-bit kernel, just for the fun and also to have a more complete idea of how an OS works under the hood.
 </br>

 An OS is mainly made out of two parts: the
 bootloader and the kernel.

The bootloader part is done by Limine, which offers a 64-bit environment out of the box (GRUB simply doesn't and you'll need to make your own "jump" from 32-bit to 64-bit), which is fine for our purpose of simply understanding how an OS works.

## Current Development Status
For the current development status check the [Roadmap Document](docs/Roadmap.md) or [The GitHub Project](https://github.com/orgs/purpleK2/projects/2)
(I, Omar, recommend the latter since it's easier to update rather than committing changes to a file every single time)

## The base of the Kenrel
The base of the kernel is the [Limine Bare Bones Template](https://wiki.osdev.org/Limine_Bare_Bones) on the [OSDev Wiki](https://wiki.osdev.org/Expanded_Main_Page) which is a fundamental source when doing OS Development

## Building the Kernel

> [!CAUTION]
> The building of this project has been only properly tested on Linux, but if you can report anything about other platforms (Windows, MacOS, Ubuntu, ...) feel free to open an issue/PR! Here is a list of currently tested (and supported) platorms

- Endeavour OS (at least one build per week)
- Arch Linux (at least one build per week)
- Debian 12 on WSL2 (Windows 10 21H2 build 19044, last tested: September 2024)
- Ubuntu 24.04 on WSL2 (Windows 11 24H2 build 26100.2033, last tested: March 2025)
- OS X Mavericks (last tested: January 2024)

> [!NOTE]  
> If you installed the cross compiler from HomeBrew/MacPorts you should compile the project with `make KCC=x86_64-elf-gcc KLD=x86_64-elf-ld`

### Testing on real hardware
Tests on real hardware are made *at least* every merging to the `main` branch is made. </br>
The hardware being tested on is the following:
- Intel Core i7-5820K (6C12T)
- ASUS X99-A
- 16GB RAM
- Sapphire Radeon R9 280

~~If you want to try the kernel with legacy booting, make sure you run `limine bios-install <your target drive>`.~~ There's no need to re-install Limine's MBR to your target drive.

### Prequisites
You need to install the following packages to build the kernel and its components. You also need a cross-compiler, the installation of the cross-compiler is in [Setting up a cross compiler](#setting-up-a-cross-compiler)


The following packages are required to build the kernel:

- `fasm`: The assembler used by this kernel
- `xorriso` and `mkisofs`: To create the ISO disk image
- `kconfig`: or more likely `kconfig-frontends` to use the `menuconfig`
- `cpio`: for creating the compressed CPIO archive
> [!NOTE]
> Fedora users: if you know how to read a `PKGBUILD` file, you can follow the commands in the AUR to install the latest version of `kconfig-frontends` (4.11.0.1 at the time of writing this) to your `/usr/bin`
- [OPTIONAL] `edk2-ovmf`: useful for running QEMU with UEFI support
- [OPTIONAL] `mtools` and `sgdisk`: for partitioning and managing the files in the virtual disk image


### Setting up a cross compiler

You will not be able to build the kernel using the C compiler on the host machine (`gcc` or `clang`). To compile it you will need a cross-compiler that targets the x86_64 (or any other 64-bit architecture) platform.

Below are two ways of installing a cross-compiler:

#### Prebuilt binaries

If you either are lazy or don't have time for compiling the toolchain, you can grab a pre-made one from [newos.org](https://newos.org/toolchains/).
You should grab the one that says `[target architecture eg. x86_64]-elf-[a version less or equal to the GCC installed in your OS]-[Linux/FreeBSD/Darwin]-x86_64.tar.xz`.
Make sure to extract the contents of the folder inside the xz to a `[target arch]-elf` directory inside the `toolchain` folder.

You should end up with a structure like this:
```
rtos
│...
├── src
│   └── ...
└── toolchain
    ├── Makefile
    └── [target architecture]-elf	<-- You should create this directory
	--- All of these folders should come from the downloaded tar archive ---
        ├── bin
        ├── include
        ├── lib
        ├── libexec
        ├── share
        └── [target architecture]-elf
```

#### Build it yourself

First, make sure to install the required dependencies for building gcc and binutils from source, and since they may vary for each distribution make sure to check out [this article on the OSDev wiki](https://wiki.osdev.org/GCC_Cross-Compiler#Installing_Dependencies) on the OSDev wiki.

Now it's time to compile the toolchain.
Thankfully, the [toolchain script made by nanobyte](https://github.com/nanobyte-dev/nanobyte_os/blob/videos/part7/build_scripts/toolchain.mk) comes in handy regarding the whole downloading and compiling binutils and gcc from source, and I integrated it here to be simply run by a single command in the project directory:

*(arguments in square brackets are optional)*

```bash
make -C toolchain [CPU_CORES=number of cpu cores for parallel jobs, defaults to $(nproc)]
```

> [!NOTE]
> If you manage to port this kernel to another architecture supported by Limine, you can add a `TARGET_BASE` or `TARGET` argument to compile a different toolchain. Same applies to the [Makefile](Makefile).

"Since it needs to compile both binutils and gcc from source, it will take a long time (depending on your CPU cores and speed), so you can go make yourself some coffee, and maybe watch the latest video from your favourite YouTube channel..."

\- [Nanobyte, 2021](https://youtu.be/TgIdFVOV_0U?t=709)

After this, you now have built your own toolchain for building this project but also any other one that relies on the base mentioned earlier (i'd suggest to update both `BINUTILS_VERSION` `GCC_VERSION` in the Makefile when an update of such package is available on your system and maybe re-run the `make -C toolchain` command, *if you always have time and will to do so*).

When you installed the cross-compiler and the dependencies you can build now build the kernel. Follow the steps below:

1. Clone the Repository and `cd` into it:
```bash
git clone --recursive https://github.com/purpleK2/purpleK2.git
cd purpleK2
```

2. Get the dependencies and build the Limine executable 
```bash
chmod +x libs/get_deps.sh
./libs/get_deps.sh src/kernel libs
make build_limine
```

> [!NOTE]
>  `src/kernel` is the kernel source code directory.
`libs` is the path to the Git submodules and the required patches (if needed)
You *can* change them, but you *shouldn't* since these are the paths in the project

### Building the ISO

Run
```bash
make menuconfig
```
This will show up a menu with options to customise the kernel build process.
For more info, you can check out the [kernel menuconfig docs](docs/menuconfig.md).
If you don't really care about such options, just hit `Save` then `Exit`.

Then run
```bash
make [optional: -j$(nproc)]
```
To build the project and create the ISO file. Now there should be a `.iso` file in the project root directory.

> [!TIP]
> You can grab an ISO from artifacts of the latest successful Github Actions build.

### Building the HDD

Yup, you heard it. I (Omar) yoinked the hdd targets from the limine C template. You can also make a virtual hard drive image.

Run
```bash
make all-hdd [optional: -j$(nproc)]
```
You should now have a `.hdd` file in the project root directory. 


## Emulating the Kernel using QEMU
The Makefile supports emulating the kernel in QEMU. This both works in native Linux and in WSL.

> [!WARNING]  
> On WSL make sure that QEMU is installed on Windows since we use passthrough execute to run it

### If you run with the ISO:

- To run it on native Linux use
```bash
make run
```

- To run it on WSL use
```bash
make run-wsl
```

### If you run with the HDD:

- To run it on native Linux use
```bash
make run-hdd
```

- To run it on WSL Linux use
```bash
make run-wsl-hdd
```


## Debugging the Kernel using QEMU and GDB

### If you run with the ISO:

To debug the kernel using QEMU and GDB run `make debug`

### If you run with the HDD:

To debug the kernel using QEMU and GDB run `make debug-hdd`

This will launch GDB using the [`debug.gdb`](debug.gdb) file as configuration. All output of the E9 debug port will be redirected into the `qemu_gdb.log` file.

> [!TIP]
> If you edit in VSCode you can set a breakpoint in code and just press `Crtl+F5` to launch the VSCode debugger. Output will be redirected to `qemu_vscode.log`

## Contributing

To contribute please read [`CONTRIBUTING.md`](CONTRIBUTING.md)

## Getting `compile_commands.json`

To get the `compile_commands.json` used by Zed and `clangd` follow the steps below:

1. Install all the dependencies and install `bear` from your distro's package manager or [install it from Brew](https://formulae.brew.sh/formula/bear)

2. In your terminal now run
```bash
bear -- make
```

Now there should be `compile_commands.json`

## License 

purpleK2 is licensed under the MIT License. See [LICENSE](LICENSE)

Copyright (c) 2024-2025 Omar and Contributors
