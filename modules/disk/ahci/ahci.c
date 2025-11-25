#include "ahci.h"

#include <memory/pmm/pmm.h>
#include <paging/paging.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern pci_device_t *pci_devices_head;

drivetype_t drivetypes[32] = { [0 ... 31] = DRV_INVALID };

void ahci_probe_ports(HBA_MEM *abar) {
    uint32_t pi = abar->pi;
    int i       = 0;
    while (pi && i < 32) {
        if (pi & 1) {
            int dt = ahci_check_port_type(&abar->ports[i]);
            switch (dt) {
            case AHCI_DEV_SATA:
                debugf_debug("SATA drive found at port %d\n", i);
                drivetypes[i] = DRV_SATA;
                break;
            case AHCI_DEV_SATAPI:
                debugf_debug("SATAPI drive found at port %d\n", i);
                drivetypes[i] = DRV_SATAPI;
                break;
            case AHCI_DEV_SEMB:
                debugf_debug("SEMB drive found at port %d\n", i);
                drivetypes[i] = DRV_SEMB;
                break;
            case AHCI_DEV_PM:
                debugf_debug("PM drive found at port %d\n", i);
                drivetypes[i] = DRV_PM;
                break;
            default:
                debugf_debug("No drive found at port %d\n", i);
                drivetypes[i] = DRV_INVALID;
                break;
            }
        }
        pi >>= 1;
        i++;
    }
}

int ahci_check_port_type(HBA_PORT *port) {
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

void ahci_port_rebase(HBA_PORT *port) {
    ahci_stop_cmd(port); // Stop command engine

    // Allocate 1 page (4KB) for Command List Base (CLB)
    uint64_t clb_phys = (uint64_t)pmm_alloc_pages(1);
    port->clb         = clb_phys;
    port->clbu        = 0;
    memset((void *)PHYS_TO_VIRTUAL(clb_phys), 0, 4096);

    // Allocate 1 page (4KB) for FIS base (FB)
    uint64_t fb_phys = (uint64_t)pmm_alloc_pages(1);
    port->fb         = fb_phys;
    port->fbu        = 0;
    memset((void *)PHYS_TO_VIRTUAL(fb_phys), 0, 4096);

    // Setup 32 command headers (each points to a command table)
    HBA_CMD_HEADER *cmdheader = (HBA_CMD_HEADER *)PHYS_TO_VIRTUAL(clb_phys);
    for (int i = 0; i < 32; i++) {
        cmdheader[i].prdtl = 8; // 8 PRDT entries per command table

        // Allocate 1 page (4KB) for command table (CTBA)
        uint64_t ctba_phys = (uint64_t)pmm_alloc_pages(1);
        cmdheader[i].ctba  = ctba_phys;
        cmdheader[i].ctbau = 0;

        memset((void *)PHYS_TO_VIRTUAL(ctba_phys), 0, 4096);
    }

    ahci_start_cmd(port); // Start command engine
}

void ahci_start_cmd(HBA_PORT *port) {
    while (port->cmd & HBA_PxCMD_CR)
        ;
    port->cmd |= HBA_PxCMD_FRE;
    port->cmd |= HBA_PxCMD_ST;
}

void ahci_stop_cmd(HBA_PORT *port) {
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

int ahci_find_cmdslot(HBA_PORT *port) {
    uint32_t slots = (port->sact | port->ci);
    for (int i = 0; i < CMD_SLOTS; i++) {
        if ((slots & 1) == 0)
            return i;
        slots >>= 1;
    }
    debugf_warn("Cannot find free command list entry\n");
    return -1;
}

bool ahci_sata_read(HBA_PORT *port, uint64_t lba, uint32_t count, void *buffer) {
    uint32_t startl = (uint32_t)lba;
    uint32_t starth = (uint32_t)(lba >> 32);

    port->is = (uint32_t)-1;
    int spin = 0;
    int slot = ahci_find_cmdslot(port);
    if (slot == -1)
        return false;

    HBA_CMD_HEADER *cmdheader = (HBA_CMD_HEADER *)PHYS_TO_VIRTUAL(port->clb);
    cmdheader += slot;
    cmdheader->cfl = sizeof(FIS_REG_H2D) / sizeof(uint32_t);
    cmdheader->w = 0; // Read
    cmdheader->prdtl = (uint16_t)((count - 1) >> 4) + 1;

    HBA_CMD_TBL *cmdtbl = (HBA_CMD_TBL *)PHYS_TO_VIRTUAL(cmdheader->ctba);
    memset(cmdtbl, 0,
           sizeof(HBA_CMD_TBL) +
               (cmdheader->prdtl - 1) * sizeof(HBA_PRDT_ENTRY));

    // Setup PRDT entries
    uint8_t *buf_ptr = (uint8_t *)buffer;  // Use uint8_t* for byte arithmetic
    uint32_t bytes_remaining = count * ahci_sata_get_block_size(port);  // Total bytes to transfer

    for (int i = 0; i < cmdheader->prdtl - 1; i++) {
        uint64_t phys_addr = pg_virtual_to_phys((uint64_t*)PHYS_TO_VIRTUAL(_get_pml4()), (uintptr_t)buf_ptr);
        //phys_addr = pg_virtual_to_phys((uint64_t*)PHYS_TO_VIRTUAL(_get_pml4()), (uintptr_t)buf_ptr);

        if ((uint64_t)buffer % PFRAME_SIZE) { // we can use pg_virtual_to_phys
            phys_addr = VIRT_TO_PHYSICAL((uintptr_t)buf_ptr);
        }
        cmdtbl->prdt_entry[i].dba = (uint32_t)phys_addr;
        cmdtbl->prdt_entry[i].dbau = (uint32_t)(phys_addr >> 32);
        cmdtbl->prdt_entry[i].dbc = 8 * 1024 - 1; // 8KB per entry
        cmdtbl->prdt_entry[i].i = 1;
        buf_ptr += 8 * 1024;
        bytes_remaining -= 8 * 1024;
    }
    
    // Last PRDT entry
    uint64_t phys_addr = pg_virtual_to_phys((uint64_t*)PHYS_TO_VIRTUAL(_get_pml4()), (uintptr_t)buf_ptr);
    //phys_addr = pg_virtual_to_phys((uint64_t*)PHYS_TO_VIRTUAL(_get_pml4()), (uintptr_t)buf_ptr);
    if ((uint64_t)buffer % PFRAME_SIZE) { // we can use pg_virtual_to_phys
        phys_addr = VIRT_TO_PHYSICAL((uintptr_t)buf_ptr);
    }
    cmdtbl->prdt_entry[cmdheader->prdtl - 1].dba = (uint32_t)phys_addr;
    cmdtbl->prdt_entry[cmdheader->prdtl - 1].dbau = (uint32_t)(phys_addr >> 32);
    cmdtbl->prdt_entry[cmdheader->prdtl - 1].dbc = bytes_remaining - 1;
    cmdtbl->prdt_entry[cmdheader->prdtl - 1].i = 1;

    // Setup command FIS
    FIS_REG_H2D *cmdfis = (FIS_REG_H2D *)(&cmdtbl->cfis);
    memset(cmdfis, 0, sizeof(FIS_REG_H2D));
    cmdfis->fis_type = FIS_TYPE_REG_H2D;
    cmdfis->c = 1;
    cmdfis->command = ATA_CMD_READ_DMA_EX;
    cmdfis->lba0 = (uint8_t)startl;
    cmdfis->lba1 = (uint8_t)(startl >> 8);
    cmdfis->lba2 = (uint8_t)(startl >> 16);
    cmdfis->device = 1 << 6; // LBA mode
    cmdfis->lba3 = (uint8_t)(startl >> 24);
    cmdfis->lba4 = (uint8_t)starth;
    cmdfis->lba5 = (uint8_t)(starth >> 8);
    cmdfis->countl = count & 0xFF;
    cmdfis->counth = (count >> 8) & 0xFF;

    // Wait for port to be ready
    while ((port->tfd & (ATA_DEV_BUSY | ATA_DEV_DRQ)) && spin < 1000000) {
        spin++;
    }
    if (spin == 1000000) {
        debugf_warn("Port is hung\n");
        return false;
    }

    // Issue command
    port->ci = 1 << slot;

    // Wait for completion
    while (1) {
        if ((port->ci & (1 << slot)) == 0)
            break;
        if (port->is & HBA_PxIS_TFES) {
            debugf_warn("Read disk error, IS=0x%x, SERR=0x%x\n", port->is, port->serr);
            return false;
        }
    }

    return true;
}

bool ahci_sata_write(HBA_PORT *port, uint64_t lba, uint32_t count, void *buffer) {
    port->is = (uint32_t)-1;
    int slot = ahci_find_cmdslot(port);
    if (slot == -1)
        return false;

    HBA_CMD_HEADER *cmdheader = (HBA_CMD_HEADER *)PHYS_TO_VIRTUAL(port->clb);
    cmdheader += slot;
    cmdheader->cfl = sizeof(FIS_REG_H2D) / sizeof(uint32_t);
    cmdheader->w = 1;
    cmdheader->prdtl = (uint16_t)((count - 1) >> 4) + 1;

    HBA_CMD_TBL *cmdtbl = (HBA_CMD_TBL *)PHYS_TO_VIRTUAL(cmdheader->ctba);
    memset(cmdtbl, 0,
           sizeof(HBA_CMD_TBL) +
               (cmdheader->prdtl - 1) * sizeof(HBA_PRDT_ENTRY));

    void *buf_ptr = buffer;
    
    for (int i = 0; i < cmdheader->prdtl - 1; i++) {
        // FIX: Convert virtual address to physical
        uint64_t phys_addr = VIRT_TO_PHYSICAL((uint64_t)buf_ptr);
        cmdtbl->prdt_entry[i].dba = (uint32_t)phys_addr;
        cmdtbl->prdt_entry[i].dbau = (uint32_t)(phys_addr >> 32);
        cmdtbl->prdt_entry[i].dbc = 8 * 1024 - 1;
        cmdtbl->prdt_entry[i].i = 1;
        buf_ptr += 4 * 1024;
        count -= 16;
    }

    cmdtbl->prdt_entry[0].dba = pg_virtual_to_phys((uint64_t *)PHYS_TO_VIRTUAL(_get_pml4()), (uintptr_t)buffer);
    cmdtbl->prdt_entry[0].dbau = (uint32_t)(pg_virtual_to_phys((uint64_t *)PHYS_TO_VIRTUAL(_get_pml4()), (uintptr_t)buffer) >> 32);
    cmdtbl->prdt_entry[cmdheader->prdtl - 1].dbc = (count << 9) - 1;
    cmdtbl->prdt_entry[cmdheader->prdtl - 1].i = 1;

    FIS_REG_H2D *cmdfis = (FIS_REG_H2D *)(&cmdtbl->cfis);
    cmdfis->fis_type = FIS_TYPE_REG_H2D;
    cmdfis->c = 1;
    cmdfis->command = 0x35;
    cmdfis->lba0 = (uint8_t)lba;
    cmdfis->lba1 = (uint8_t)(lba >> 8);
    cmdfis->lba2 = (uint8_t)(lba >> 16);
    cmdfis->device = 1 << 6;
    cmdfis->lba3 = (uint8_t)(lba >> 24);
    cmdfis->lba4 = (uint8_t)(lba >> 32);
    cmdfis->lba5 = (uint8_t)(lba >> 40);
    cmdfis->countl = count & 0xFF;
    cmdfis->counth = (count >> 8) & 0xFF;

    int spin = 0;
    while ((port->tfd & (ATA_DEV_BUSY | ATA_DEV_DRQ)) && spin < 1000000)
        spin++;

    if (spin == 1000000) {
        debugf_warn("Port is hung\n");
        return FALSE;
    }

    port->ci = 1 << slot;

    while (1) {
        if ((port->ci & (1 << slot)) == 0)
            break;
        if (port->is & HBA_PxIS_TFES) {
            debugf_warn("Write disk error\n");
            return FALSE;
        }
    }

    return TRUE;
}

pci_device_t *ahci_detect_controller() {
    pci_device_t *current = pci_devices_head;
    while (current) {
        const char *name_1 = pci_get_class_name(current->class_code);
        if (strcmp(name_1, "Mass Storage Controller") == 0) {
            const char *name =
                pci_get_subclass_name(current->class_code, current->subclass);
            if (strcmp(name, "SATA Controller") == 0) {
                return current;
            }
        }
        current = current->next;
    }
    return NULL;
}

bool ahci_atapi_read(HBA_PORT *port, uint64_t lba, uint32_t count, void *buffer) {
    port->is = (uint32_t)-1;
    int slot = ahci_find_cmdslot(port);
    if (slot == -1)
        return false;

    HBA_CMD_HEADER *cmdheader = (HBA_CMD_HEADER *)PHYS_TO_VIRTUAL(port->clb);
    cmdheader += slot;
    cmdheader->cfl = sizeof(FIS_REG_H2D) / sizeof(uint32_t);
    cmdheader->w = 0;
    cmdheader->a = 1;
    cmdheader->prdtl = 1;

    HBA_CMD_TBL *cmdtbl = (HBA_CMD_TBL *)PHYS_TO_VIRTUAL(cmdheader->ctba);
    memset(cmdtbl, 0, sizeof(HBA_CMD_TBL) + sizeof(HBA_PRDT_ENTRY));

    cmdtbl->prdt_entry[0].dba = pg_virtual_to_phys((uint64_t *)PHYS_TO_VIRTUAL(_get_pml4()), (uintptr_t)buffer);
    cmdtbl->prdt_entry[0].dbau = (uint32_t)(pg_virtual_to_phys((uint64_t *)PHYS_TO_VIRTUAL(_get_pml4()), (uintptr_t)buffer) >> 32);
    cmdtbl->prdt_entry[0].dbc = (count * ATAPI_SECTOR_SIZE) - 1;
    cmdtbl->prdt_entry[0].i = 1;

    FIS_REG_H2D *cmdfis = (FIS_REG_H2D *)(&cmdtbl->cfis);
    cmdfis->fis_type = FIS_TYPE_REG_H2D;
    cmdfis->c = 1;
    cmdfis->command = ATA_CMD_PACKET;
    cmdfis->device = 0;
    cmdfis->featurel = 0; // DMA
    cmdfis->featureh = 0;
    cmdfis->lba1 = (count * ATAPI_SECTOR_SIZE) & 0xFF;
    cmdfis->lba2 = (count * ATAPI_SECTOR_SIZE) >> 8;

    uint8_t *acmd = cmdtbl->acmd;
    memset(acmd, 0, 16);
    acmd[0] = SCSI_CMD_READ_10;
    acmd[2] = (lba >> 24) & 0xFF;
    acmd[3] = (lba >> 16) & 0xFF;
    acmd[4] = (lba >> 8) & 0xFF;
    acmd[5] = lba & 0xFF;
    acmd[7] = (count >> 8) & 0xFF;
    acmd[8] = count & 0xFF;

    int spin = 0;
    while ((port->tfd & (ATA_DEV_BUSY | ATA_DEV_DRQ)) && spin < 1000000) {
        spin++;
    }
    if (spin == 1000000) {
        debugf_warn("Port is hung\n");
        return false;
    }

    port->ci = 1 << slot;

    while (1) {
        if ((port->ci & (1 << slot)) == 0)
            break;
        if (port->is & HBA_PxIS_TFES) {
            debugf_warn("ATAPI read error\n");
            return false;
        }
    }

    if (port->is & HBA_PxIS_TFES) {
        debugf_warn("ATAPI read error\n");
        return false;
    }

    return true;
}

uint32_t ahci_atapi_get_capacity(HBA_PORT *port) {
    uint8_t buffer[8];
    
    port->is = (uint32_t)-1;
    int slot = ahci_find_cmdslot(port);
    if (slot == -1)
        return 0;

    HBA_CMD_HEADER *cmdheader = (HBA_CMD_HEADER *)PHYS_TO_VIRTUAL(port->clb);
    cmdheader += slot;
    cmdheader->cfl = sizeof(FIS_REG_H2D) / sizeof(uint32_t);
    cmdheader->w = 0;
    cmdheader->a = 1;
    cmdheader->prdtl = 1;

    HBA_CMD_TBL *cmdtbl = (HBA_CMD_TBL *)PHYS_TO_VIRTUAL(cmdheader->ctba);
    memset(cmdtbl, 0, sizeof(HBA_CMD_TBL) + sizeof(HBA_PRDT_ENTRY));

    cmdtbl->prdt_entry[0].dba = pg_virtual_to_phys((uint64_t *)PHYS_TO_VIRTUAL(_get_pml4()), (uintptr_t)buffer);
    cmdtbl->prdt_entry[0].dbau = (uint32_t)(pg_virtual_to_phys((uint64_t *)PHYS_TO_VIRTUAL(_get_pml4()), (uintptr_t)buffer) >> 32);
    cmdtbl->prdt_entry[0].dbc = 7;
    cmdtbl->prdt_entry[0].i = 1;

    FIS_REG_H2D *cmdfis = (FIS_REG_H2D *)(&cmdtbl->cfis);
    cmdfis->fis_type = FIS_TYPE_REG_H2D;
    cmdfis->c = 1;
    cmdfis->command = ATA_CMD_PACKET;
    cmdfis->featurel = 0;
    cmdfis->lba1 = 8;
    cmdfis->lba2 = 0;

    uint8_t *acmd = cmdtbl->acmd;
    memset(acmd, 0, 16);
    acmd[0] = SCSI_CMD_READ_CAPACITY;

    int spin = 0;
    while ((port->tfd & (ATA_DEV_BUSY | ATA_DEV_DRQ)) && spin < 1000000)
        spin++;
    
    if (spin == 1000000)
        return 0;

    port->ci = 1 << slot;

    while (1) {
        if ((port->ci & (1 << slot)) == 0)
            break;
        if (port->is & HBA_PxIS_TFES)
            return 0;
    }

    uint32_t capacity = ((uint32_t)buffer[0] << 24) |
                       ((uint32_t)buffer[1] << 16) |
                       ((uint32_t)buffer[2] << 8) |
                       buffer[3];
    
    return capacity + 1;
}

bool ahci_atapi_is_writable(HBA_PORT *port) {
    uint8_t buffer[8];
    
    port->is = (uint32_t)-1;
    int slot = ahci_find_cmdslot(port);
    if (slot == -1)
        return false;

    HBA_CMD_HEADER *cmdheader = (HBA_CMD_HEADER *)PHYS_TO_VIRTUAL(port->clb);
    cmdheader += slot;
    cmdheader->cfl = sizeof(FIS_REG_H2D) / sizeof(uint32_t);
    cmdheader->w = 0;
    cmdheader->a = 1;
    cmdheader->prdtl = 1;

    HBA_CMD_TBL *cmdtbl = (HBA_CMD_TBL *)PHYS_TO_VIRTUAL(cmdheader->ctba);
    memset(cmdtbl, 0, sizeof(HBA_CMD_TBL) + sizeof(HBA_PRDT_ENTRY));

    cmdtbl->prdt_entry[0].dba = pg_virtual_to_phys((uint64_t *)PHYS_TO_VIRTUAL(_get_pml4()), (uintptr_t)buffer);
    cmdtbl->prdt_entry[0].dbau = (uint32_t)(pg_virtual_to_phys((uint64_t *)PHYS_TO_VIRTUAL(_get_pml4()), (uintptr_t)buffer) >> 32);
    cmdtbl->prdt_entry[0].dbc = 7;
    cmdtbl->prdt_entry[0].i = 1;

    FIS_REG_H2D *cmdfis = (FIS_REG_H2D *)(&cmdtbl->cfis);
    cmdfis->fis_type = FIS_TYPE_REG_H2D;
    cmdfis->c = 1;
    cmdfis->command = ATA_CMD_PACKET;
    cmdfis->featurel = 0;
    cmdfis->lba1 = 8;
    cmdfis->lba2 = 0;

    uint8_t *acmd = cmdtbl->acmd;
    memset(acmd, 0, 16);
    acmd[0] = 0x5A;
    acmd[2] = 0x2A;
    acmd[7] = 0;
    acmd[8] = 8;

    int spin = 0;
    while ((port->tfd & (ATA_DEV_BUSY | ATA_DEV_DRQ)) && spin < 1000000)
        spin++;
    
    if (spin == 1000000)
        return false;

    port->ci = 1 << slot;

    while (1) {
        if ((port->ci & (1 << slot)) == 0)
            break;
        if (port->is & HBA_PxIS_TFES)
            return false;
    }

    return !(buffer[2] & 0x80);
}

bool ahci_atapi_write(HBA_PORT *port, uint64_t lba, uint32_t count, void *buffer) {
    port->is = (uint32_t)-1;
    int slot = ahci_find_cmdslot(port);
    if (slot == -1)
        return false;

    HBA_CMD_HEADER *cmdheader = (HBA_CMD_HEADER *)PHYS_TO_VIRTUAL(port->clb);
    cmdheader += slot;
    cmdheader->cfl = sizeof(FIS_REG_H2D) / sizeof(uint32_t);
    cmdheader->w = 1;
    cmdheader->a = 1;
    cmdheader->prdtl = 1;

    HBA_CMD_TBL *cmdtbl = (HBA_CMD_TBL *)PHYS_TO_VIRTUAL(cmdheader->ctba);
    memset(cmdtbl, 0, sizeof(HBA_CMD_TBL) + sizeof(HBA_PRDT_ENTRY));

    cmdtbl->prdt_entry[0].dba = pg_virtual_to_phys((uint64_t *)PHYS_TO_VIRTUAL(_get_pml4()), (uintptr_t)buffer);
    cmdtbl->prdt_entry[0].dbau = (uint32_t)(pg_virtual_to_phys((uint64_t *)PHYS_TO_VIRTUAL(_get_pml4()), (uintptr_t)buffer) >> 32);
    cmdtbl->prdt_entry[0].dbc = (count * ATAPI_SECTOR_SIZE) - 1;
    cmdtbl->prdt_entry[0].i = 1;

    FIS_REG_H2D *cmdfis = (FIS_REG_H2D *)(&cmdtbl->cfis);
    cmdfis->fis_type = FIS_TYPE_REG_H2D;
    cmdfis->c = 1;
    cmdfis->command = ATA_CMD_PACKET;
    cmdfis->device = 0;
    cmdfis->featurel = 0; // DMA
    cmdfis->featureh = 0;
    cmdfis->lba1 = (count * ATAPI_SECTOR_SIZE) & 0xFF;
    cmdfis->lba2 = (count * ATAPI_SECTOR_SIZE) >> 8;

    uint8_t *acmd = cmdtbl->acmd;
    memset(acmd, 0, 16);
    acmd[0] = 0x2A;
    acmd[2] = (lba >> 24) & 0xFF;
    acmd[3] = (lba >> 16) & 0xFF;
    acmd[4] = (lba >> 8) & 0xFF;
    acmd[5] = lba & 0xFF;
    acmd[7] = (count >> 8) & 0xFF;
    acmd[8] = count & 0xFF;

    int spin = 0;
    while ((port->tfd & (ATA_DEV_BUSY | ATA_DEV_DRQ)) && spin < 1000000) {
        spin++;
    }
    if (spin == 1000000) {
        debugf_warn("Port is hung\n");
        return false;
    }

    port->ci = 1 << slot;

    while (1) {
        if ((port->ci & (1 << slot)) == 0)
            break;
        if (port->is & HBA_PxIS_TFES) {
            debugf_warn("ATAPI write error\n");
            return false;
        }
    }

    if (port->is & HBA_PxIS_TFES) {
        debugf_warn("ATAPI write error\n");
        return false;
    }

    return true;
}

uint64_t ahci_sata_get_capacity(HBA_PORT *port) {
    port->is = (uint32_t)-1;
    int slot = ahci_find_cmdslot(port);
    if (slot == -1)
        return 0;

    uint16_t identify_buffer[256];
    memset(identify_buffer, 0, 512);

    HBA_CMD_HEADER *cmdheader = (HBA_CMD_HEADER *)PHYS_TO_VIRTUAL(port->clb);
    cmdheader += slot;
    cmdheader->cfl = sizeof(FIS_REG_H2D) / sizeof(uint32_t);
    cmdheader->w = 0;
    cmdheader->prdtl = 1;

    HBA_CMD_TBL *cmdtbl = (HBA_CMD_TBL *)PHYS_TO_VIRTUAL(cmdheader->ctba);
    memset(cmdtbl, 0, sizeof(HBA_CMD_TBL) + sizeof(HBA_PRDT_ENTRY));

    uint64_t phys_addr = VIRT_TO_PHYSICAL((uint64_t)identify_buffer);
    cmdtbl->prdt_entry[0].dba = (uint32_t)phys_addr;
    cmdtbl->prdt_entry[0].dbau = (uint32_t)(phys_addr >> 32);
    cmdtbl->prdt_entry[0].dbc = 511;
    cmdtbl->prdt_entry[0].i = 1;

    FIS_REG_H2D *cmdfis = (FIS_REG_H2D *)(&cmdtbl->cfis);
    cmdfis->fis_type = FIS_TYPE_REG_H2D;
    cmdfis->c = 1;
    cmdfis->command = ATA_CMD_IDENTIFY;
    cmdfis->device = 0;

    int spin = 0;
    while ((port->tfd & (ATA_DEV_BUSY | ATA_DEV_DRQ)) && spin < 1000000) {
        spin++;
    }
    if (spin == 1000000) {
        debugf_warn("Port is hung during IDENTIFY\n");
        return 0;
    }

    port->ci = 1 << slot;

    while (1) {
        if ((port->ci & (1 << slot)) == 0)
            break;
        if (port->is & HBA_PxIS_TFES) {
            debugf_warn("IDENTIFY command failed\n");
            return 0;
        }
    }

    if (port->is & HBA_PxIS_TFES) {
        debugf_warn("IDENTIFY command error\n");
        return 0;
    }

    if (identify_buffer[83] & (1 << 10)) {
        uint64_t capacity = ((uint64_t)identify_buffer[103] << 48) |
                           ((uint64_t)identify_buffer[102] << 32) |
                           ((uint64_t)identify_buffer[101] << 16) |
                           ((uint64_t)identify_buffer[100]);
        return capacity;
    } else {
        uint32_t capacity = ((uint32_t)identify_buffer[61] << 16) |
                           ((uint32_t)identify_buffer[60]);
        return (uint64_t)capacity;
    }
}

uint32_t ahci_sata_get_block_size(HBA_PORT *port) {
    port->is = (uint32_t)-1;
    int slot = ahci_find_cmdslot(port);
    if (slot == -1)
        return 512;

    uint16_t identify_buffer[256];
    memset(identify_buffer, 0, 512);

    HBA_CMD_HEADER *cmdheader = (HBA_CMD_HEADER *)PHYS_TO_VIRTUAL(port->clb);
    cmdheader += slot;
    cmdheader->cfl = sizeof(FIS_REG_H2D) / sizeof(uint32_t);
    cmdheader->w = 0;
    cmdheader->prdtl = 1;

    HBA_CMD_TBL *cmdtbl = (HBA_CMD_TBL *)PHYS_TO_VIRTUAL(cmdheader->ctba);
    memset(cmdtbl, 0, sizeof(HBA_CMD_TBL) + sizeof(HBA_PRDT_ENTRY));

    uint64_t phys_addr = VIRT_TO_PHYSICAL((uint64_t)identify_buffer);
    cmdtbl->prdt_entry[0].dba = (uint32_t)phys_addr;
    cmdtbl->prdt_entry[0].dbau = (uint32_t)(phys_addr >> 32);
    cmdtbl->prdt_entry[0].dbc = 511;
    cmdtbl->prdt_entry[0].i = 1;

    FIS_REG_H2D *cmdfis = (FIS_REG_H2D *)(&cmdtbl->cfis);
    cmdfis->fis_type = FIS_TYPE_REG_H2D;
    cmdfis->c = 1;
    cmdfis->command = ATA_CMD_IDENTIFY;
    cmdfis->device = 0;

    int spin = 0;
    while ((port->tfd & (ATA_DEV_BUSY | ATA_DEV_DRQ)) && spin < 1000000) {
        spin++;
    }
    if (spin == 1000000) {
        debugf_warn("Port is hung during IDENTIFY\n");
        return 512;
    }

    port->ci = 1 << slot;

    while (1) {
        if ((port->ci & (1 << slot)) == 0)
            break;
        if (port->is & HBA_PxIS_TFES) {
            debugf_warn("IDENTIFY command failed\n");
            return 512;
        }
    }

    if (port->is & HBA_PxIS_TFES) {
        debugf_warn("IDENTIFY command error\n");
        return 512;
    }
    
    uint16_t word106 = identify_buffer[106];
    uint32_t logical_sector_size = 512;
    
    if (word106 & (1 << 12)) {
        uint32_t words_per_sector = ((uint32_t)identify_buffer[118] << 16) | 
                                    ((uint32_t)identify_buffer[117]);
        logical_sector_size = words_per_sector * 2;
    }
    
    return logical_sector_size;
}
