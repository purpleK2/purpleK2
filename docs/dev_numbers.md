# PurpleK2 Device Numbers

In here all PurpleK2 device numbers (Major and Minor) are documented

## Major 0: Unused

If you see a device with the major device number 0, its an invalid device and should be reported to the developers of the driver

## Major 1: Disk Devices

Major device number 1 is reserved for Disk Devices (like Disks, Partitons, NVMe, etc.)

### 1:0: Partition Device

This is for a partition on any disk device (so 1 + another minor). The disk partitons are usually formatted like `[disk_name][partition_number]` so like `sda1` for the first partiton on the first SATA drive.

### 1:1: AHCI / SATA Drives

Minor 1 is reserved for AHCI / SATA drives. These also get the prefix `sd` + the drive letter so like `sda`, `sdb`, etc.

### 1:2: ATAPI Optical Drives

Minor 2 is reserved for ATAPI (SCSI) optical drives. This includes CD-ROMs, CD-RWs, DVDs and BlueRays. They also get the prefix `opt` followed by the drive letter just for SATA drives so `opta`, `optb`, etc.

### 1:3: Floppy Drives

Minor 3 is reserved for floppy drives. They get the prefix `fd`, so `fda`, `fdb`, etc.
