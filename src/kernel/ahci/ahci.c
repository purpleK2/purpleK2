#include "ahci.h"

#include <stdio.h>
#include <string.h>

static int check_type(HBA_PORT *port) {
    uint32_t ssts = port->ssts;
    uint8_t ipm   = (ssts >> 8) & 0x0F;
    uint8_t det   = ssts & 0x0F;

    if (det != HBA_PORT_DET_PRESENT)
        return AHCI_DEV_NULL;
    if (ipm != HBA_PORT_IPM_ACTIVE)
        return AHCI_DEV_NULL;

    switch (port->sig) {
    case SATA_SIG_ATAPI:
        return AHCI_DEV_SATAPI;
    case SATA_SIG_SEMB:
        return AHCI_DEV_SEMB;
    case SATA_SIG_PM:
        return AHCI_DEV_PM;
    default:
        return AHCI_DEV_SATA;
    }
}

void probe_port(HBA_MEM *abar) {
    uint32_t pi = abar->pi;
    int i       = 0;
    while (pi && i < 32) {
        if (pi & 1) {
            int dt = check_type(&abar->ports[i]);
            switch (dt) {
            case AHCI_DEV_SATA:
                debugf_debug("SATA drive found at port %d\n", i);
                break;
            case AHCI_DEV_SATAPI:
                debugf_debug("SATAPI drive found at port %d\n", i);
                break;
            case AHCI_DEV_SEMB:
                debugf_debug("SEMB drive found at port %d\n", i);
                break;
            case AHCI_DEV_PM:
                debugf_debug("PM drive found at port %d\n", i);
                break;
            default:
                debugf_debug("No drive found at port %d\n", i);
                break;
            }
        }
        pi >>= 1;
        i++;
    }
}

void port_rebase(HBA_PORT *port, int portno) {
    stop_cmd(port);
    port->clb  = AHCI_BASE + (portno << 10);
    port->clbu = 0;
    memset((void *)(port->clb), 0, 1024);
    port->fb  = AHCI_BASE + (32 << 10) + (portno << 8);
    port->fbu = 0;
    memset((void *)(port->fb), 0, 256);

    HBA_CMD_HEADER *cmdheader = (HBA_CMD_HEADER *)(port->clb);
    for (int i = 0; i < 32; i++) {
        cmdheader[i].prdtl = 8;
        cmdheader[i].ctba  = AHCI_BASE + (40 << 10) + (portno << 13) + (i << 8);
        cmdheader[i].ctbau = 0;
        memset((void *)cmdheader[i].ctba, 0, 256);
    }

    start_cmd(port);
}

void start_cmd(HBA_PORT *port) {
    while (port->cmd & HBA_PxCMD_CR)
        ;
    port->cmd |= HBA_PxCMD_FRE;
    port->cmd |= HBA_PxCMD_ST;
}

void stop_cmd(HBA_PORT *port) {
    port->cmd &= ~HBA_PxCMD_ST;
    port->cmd &= ~HBA_PxCMD_FRE;
    while (1) {
        if (port->cmd & HBA_PxCMD_FR)
            continue;
        if (port->cmd & HBA_PxCMD_CR)
            continue;
        break;
    }
}

bool READ(HBA_PORT *port, uint32_t startl, uint32_t starth, uint32_t count,
          uint16_t *buf) {
    port->is = (uint32_t)-1;
    int spin = 0;
    int slot = find_cmdslot(port);
    if (slot == -1)
        return false;

    HBA_CMD_HEADER *cmdheader  = (HBA_CMD_HEADER *)port->clb;
    cmdheader                 += slot;
    cmdheader->cfl             = sizeof(FIS_REG_H2D) / sizeof(uint32_t);
    cmdheader->w               = 0;
    cmdheader->prdtl           = (uint16_t)((count - 1) >> 4) + 1;

    HBA_CMD_TBL *cmdtbl = (HBA_CMD_TBL *)(cmdheader->ctba);
    memset(cmdtbl, 0,
           sizeof(HBA_CMD_TBL) +
               (cmdheader->prdtl - 1) * sizeof(HBA_PRDT_ENTRY));

    for (int i = 0; i < cmdheader->prdtl - 1; i++) {
        cmdtbl->prdt_entry[i].dba  = (uint32_t)buf;
        cmdtbl->prdt_entry[i].dbc  = 8 * 1024 - 1;
        cmdtbl->prdt_entry[i].i    = 1;
        buf                       += 4 * 1024;
        count                     -= 16;
    }

    int i;
    cmdtbl->prdt_entry[i].dba = (uint32_t)buf;
    cmdtbl->prdt_entry[i].dbc = (count << 9) - 1;
    cmdtbl->prdt_entry[i].i   = 1;

    FIS_REG_H2D *cmdfis = (FIS_REG_H2D *)(&cmdtbl->cfis);
    cmdfis->fis_type    = FIS_TYPE_REG_H2D;
    cmdfis->c           = 1;
    cmdfis->command     = ATA_CMD_READ_DMA_EX;

    cmdfis->lba0   = (uint8_t)startl;
    cmdfis->lba1   = (uint8_t)(startl >> 8);
    cmdfis->lba2   = (uint8_t)(startl >> 16);
    cmdfis->device = 1 << 6;
    cmdfis->lba3   = (uint8_t)(startl >> 24);
    cmdfis->lba4   = (uint8_t)starth;
    cmdfis->lba5   = (uint8_t)(starth >> 8);

    cmdfis->countl = count & 0xFF;
    cmdfis->counth = (count >> 8) & 0xFF;

    while ((port->tfd & (ATA_DEV_BUSY | ATA_DEV_DRQ)) && spin < 1000000) {
        spin++;
    }
    if (spin == 1000000) {
        kprintf_panic("Port is hung\n");
        return FALSE;
    }

    port->ci = 1 << slot;

    while (1) {
        if ((port->ci & (1 << slot)) == 0)
            break;
        if (port->is & HBA_PxIS_TFES) {
            kprintf_panic("Read disk error\n");
            return FALSE;
        }
    }

    if (port->is & HBA_PxIS_TFES) {
        kprintf_panic("Read disk error\n");
        return FALSE;
    }

    return true;
}

int find_cmdslot(HBA_PORT *port) {
    uint32_t slots = (port->sact | port->ci);
    for (int i = 0; i < CMD_SLOTS; i++) {
        if ((slots & 1) == 0)
            return i;
        slots >>= 1;
    }
    kprintf_panic("Cannot find free command list entry\n");
    return -1;
}

void test_ahci() {
    FIS_REG_H2D fis;
    memset(&fis, 0, sizeof(FIS_REG_H2D));
    fis.fis_type = FIS_TYPE_REG_H2D;
    fis.command  = ATA_CMD_IDENTIFY;
    fis.device   = 0;
    fis.c        = 1;
}

void detect_disk(HBA_MEM *abar) {
    probe_port(abar);
}

bool ahci_read(HBA_PORT *port, uint64_t lba, uint32_t count, void *buffer) {
    return READ(port, (uint32_t)lba, (uint32_t)(lba >> 32), count,
                (uint16_t *)buffer);
}

bool ahci_write(HBA_PORT *port, uint64_t lba, uint32_t count, void *buffer) {
    port->is = (uint32_t)-1;
    int slot = find_cmdslot(port);
    if (slot == -1)
        return false;

    HBA_CMD_HEADER *cmdheader  = (HBA_CMD_HEADER *)port->clb;
    cmdheader                 += slot;
    cmdheader->cfl             = sizeof(FIS_REG_H2D) / sizeof(uint32_t);
    cmdheader->w               = 1;
    cmdheader->prdtl           = (uint16_t)((count - 1) >> 4) + 1;

    HBA_CMD_TBL *cmdtbl = (HBA_CMD_TBL *)(cmdheader->ctba);
    memset(cmdtbl, 0,
           sizeof(HBA_CMD_TBL) +
               (cmdheader->prdtl - 1) * sizeof(HBA_PRDT_ENTRY));

    for (int i = 0; i < cmdheader->prdtl - 1; i++) {
        cmdtbl->prdt_entry[i].dba  = (uint32_t)buffer;
        cmdtbl->prdt_entry[i].dbc  = 8 * 1024 - 1;
        cmdtbl->prdt_entry[i].i    = 1;
        buffer                    += 4 * 1024;
        count                     -= 16;
    }

    cmdtbl->prdt_entry[cmdheader->prdtl - 1].dba = (uint32_t)buffer;
    cmdtbl->prdt_entry[cmdheader->prdtl - 1].dbc = (count << 9) - 1;
    cmdtbl->prdt_entry[cmdheader->prdtl - 1].i   = 1;

    FIS_REG_H2D *cmdfis = (FIS_REG_H2D *)(&cmdtbl->cfis);
    cmdfis->fis_type    = FIS_TYPE_REG_H2D;
    cmdfis->c           = 1;
    cmdfis->command     = 0x35;

    cmdfis->lba0   = (uint8_t)lba;
    cmdfis->lba1   = (uint8_t)(lba >> 8);
    cmdfis->lba2   = (uint8_t)(lba >> 16);
    cmdfis->device = 1 << 6;
    cmdfis->lba3   = (uint8_t)(lba >> 24);
    cmdfis->lba4   = (uint8_t)(lba >> 32);
    cmdfis->lba5   = (uint8_t)(lba >> 40);

    cmdfis->countl = count & 0xFF;
    cmdfis->counth = (count >> 8) & 0xFF;

    int spin = 0;
    while ((port->tfd & (ATA_DEV_BUSY | ATA_DEV_DRQ)) && spin < 1000000)
        spin++;

    if (spin == 1000000) {
        kprintf_panic("Port is hung\n");
        return FALSE;
    }

    port->ci = 1 << slot;

    while (1) {
        if ((port->ci & (1 << slot)) == 0)
            break;
        if (port->is & HBA_PxIS_TFES) {
            kprintf_panic("Write disk error\n");
            return FALSE;
        }
    }

    return TRUE;
}

void test_ahci_operations(HBA_MEM *abar) {
    detect_disk(abar);

    char buffer[512] = {0};
    if (ahci_read(&abar->ports[0], 0, 1, buffer))
        debugf_debug("Read successful!\n");
    else
        debugf_warn("Read failed!\n");

    strcpy(buffer, "Hello, AHCI!");
    if (ahci_write(&abar->ports[0], 0, 1, buffer))
        debugf_debug("Write successful!\n");
    else
        debugf_warn("Write failed!\n");
}
