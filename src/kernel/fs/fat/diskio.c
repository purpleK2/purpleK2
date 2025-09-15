/*-----------------------------------------------------------------------*/
/* Low level disk I/O module SKELETON for FatFs     (C)ChaN, 2025        */
/*-----------------------------------------------------------------------*/
/* If a working storage control module is available, it should be        */
/* attached to the FatFs via a glue function rather than modifying it.   */
/* This is an example of glue functions to attach various exsisting      */
/* storage control modules to the FatFs module with a defined API.       */
/*-----------------------------------------------------------------------*/

#include "diskio.h" /* Declarations FatFs MAI */
#include "ahci/ahci.h"
#include "ff.h" /* Basic definitions of FatFs */

/* Example: Mapping of physical drive number for each drive */
#define DEV_AHCI 0

/*-----------------------------------------------------------------------*/
/* Get Drive Status                                                      */
/*-----------------------------------------------------------------------*/

DSTATUS disk_status(BYTE pdrv) {
    DSTATUS stat;
    int result;

    switch (pdrv) {
    case DEV_AHCI:
        return RES_OK;
    }
    return STA_NOINIT;
}

/*-----------------------------------------------------------------------*/
/* Inidialize a Drive                                                    */
/*-----------------------------------------------------------------------*/

DSTATUS
disk_initialize(BYTE pdrv) {
    DSTATUS stat;
    int result;

    switch (pdrv) {
    case DEV_AHCI:
        return RES_OK;
    }
    return STA_NOINIT;
}

/*-----------------------------------------------------------------------*/
/* Read Sector(s)                                                        */
/*-----------------------------------------------------------------------*/

DRESULT disk_read(BYTE pdrv,  /* Physical drive nmuber to identify the drive */
                  BYTE *buff, /* Data buffer to store read data */
                  LBA_t sector, /* Start sector in LBA */
                  UINT count    /* Number of sectors to read */
) {
    DRESULT res;
    int result;

    switch (pdrv) {
    case DEV_AHCI: {

        int sata_port = get_sata_port(abar_mem);
        ahci_read(&abar_mem->ports[sata_port], 2048 + sector, count, buff);

        return RES_OK;
    }
    }

    return RES_PARERR;
}

/*-----------------------------------------------------------------------*/
/* Write Sector(s)                                                       */
/*-----------------------------------------------------------------------*/

#if FF_FS_READONLY == 0

DRESULT disk_write(BYTE pdrv, /* Physical drive nmuber to identify the drive */
                   const BYTE *buff, /* Data to be written */
                   LBA_t sector,     /* Start sector in LBA */
                   UINT count        /* Number of sectors to write */
) {

    switch (pdrv) {
    case DEV_AHCI: {

        int sata_port = get_sata_port(abar_mem);
        ahci_write(&abar_mem->ports[sata_port], 2048 + sector, count, buff);
        return RES_OK;
    }
    }

    return RES_PARERR;
}

#endif

/*-----------------------------------------------------------------------*/
/* Miscellaneous Functions                                               */
/*-----------------------------------------------------------------------*/

DRESULT disk_ioctl(BYTE pdrv, /* Physical drive nmuber (0..) */
                   BYTE cmd,  /* Control code */
                   void *buff /* Buffer to send/receive control data */
) {
    DRESULT res;
    int result;

    switch (pdrv) { return RES_OK; }

    return RES_PARERR;
}

DWORD get_fattime(void) {
    return 0;
}
