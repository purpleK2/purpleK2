#include "ahci.h"

#include <stdio.h>
#include <string.h>
#include <memory/pmm/pmm.h>
#include <paging/paging.h>

extern pci_device_t *pci_devices_head;

void probe_port(HBA_MEM *abar) {
    uint32_t pi = abar->pi;
    int i       = 0;
    while (pi && i < 32) {
        if (pi & 1) {
            int dt = check_type(&abar->ports[i]);
            switch (dt) {
            case AHCI_DEV_SATA:
                mprintf("SATA drive found at port %d\n", i);
                break;
            case AHCI_DEV_SATAPI:
                mprintf("SATAPI drive found at port %d\n", i);
                break;
            case AHCI_DEV_SEMB:
                mprintf("SEMB drive found at port %d\n", i);
                break;
            case AHCI_DEV_PM:
                mprintf("PM drive found at port %d\n", i);
                break;
            default:
                mprintf("No drive found at port %d\n", i);
                break;
            }
        }
        pi >>= 1;
        i++;
    }
}

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

int get_sata_port(HBA_MEM *abar) {
    uint32_t pi = abar->pi;
    int i       = 0;
    while (pi && i < 32) {
        if (pi & 1) {
            int dt = check_type(&abar->ports[i]);
            switch (dt) {
            case AHCI_DEV_SATA:
                return i;
                break;
            default:
                break;
            }
        }
        pi >>= 1;
        i++;
    }
}

void port_rebase(HBA_PORT *port) {
    stop_cmd(port);	// Stop command engine

    // Allocate 1 page (4KB) for Command List Base (CLB)
    uint64_t clb_phys = (uint64_t)pmm_alloc_pages(1);
    port->clb = clb_phys;
    port->clbu = 0;
    memset((void*)PHYS_TO_VIRTUAL(clb_phys), 0, 4096);

    // Allocate 1 page (4KB) for FIS base (FB)
    uint64_t fb_phys = (uint64_t)pmm_alloc_pages(1);
    port->fb = fb_phys;
    port->fbu = 0;
    memset((void*)PHYS_TO_VIRTUAL(fb_phys), 0, 4096);

    // Setup 32 command headers (each points to a command table)
    HBA_CMD_HEADER *cmdheader = (HBA_CMD_HEADER*)PHYS_TO_VIRTUAL(clb_phys);
    for (int i = 0; i < 32; i++) {
        cmdheader[i].prdtl = 8;	// 8 PRDT entries per command table

        // Allocate 1 page (4KB) for command table (CTBA)
        uint64_t ctba_phys = (uint64_t)pmm_alloc_pages(1);
        cmdheader[i].ctba = ctba_phys;
        cmdheader[i].ctbau = 0;

        memset((void*)PHYS_TO_VIRTUAL(ctba_phys), 0, 4096);
    }

    start_cmd(port);	// Start command engine
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

bool READ(HBA_PORT *port, uint32_t startl, uint32_t starth, uint32_t count, uint16_t* buf)
{
	port->is = (uint32_t) -1;		// Clear pending interrupt bits
	int spin = 0; // Spin lock timeout counter
	int slot = find_cmdslot(port);
	if (slot == -1)
		return false;

	HBA_CMD_HEADER *cmdheader = (HBA_CMD_HEADER*)PHYS_TO_VIRTUAL(port->clb);
	cmdheader += slot;
	cmdheader->cfl = sizeof(FIS_REG_H2D)/sizeof(uint32_t);	// Command FIS size
	cmdheader->w = 0;		// Read from device
	cmdheader->prdtl = (uint16_t)((count-1)>>4) + 1;	// PRDT entries count

	HBA_CMD_TBL *cmdtbl = (HBA_CMD_TBL*)PHYS_TO_VIRTUAL(cmdheader->ctba);
	memset(cmdtbl, 0, sizeof(HBA_CMD_TBL) +
 		(cmdheader->prdtl-1)*sizeof(HBA_PRDT_ENTRY));

	// 8K bytes (16 sectors) per PRDT

    int i;

	for (i=0; i<cmdheader->prdtl-1; i++)
	{
		cmdtbl->prdt_entry[i].dba = (uint32_t) buf;
		cmdtbl->prdt_entry[i].dbc = 8*1024-1;	// 8K bytes (this value should always be set to 1 less than the actual value)
		cmdtbl->prdt_entry[i].i = 1;
		buf += 4*1024;	// 4K words
		count -= 16;	// 16 sectors
	}
	// Last entry
	cmdtbl->prdt_entry[i].dba = (uint32_t) buf;
	cmdtbl->prdt_entry[i].dbc = (count<<9)-1;	// 512 bytes per sector
	cmdtbl->prdt_entry[i].i = 1;

	// Setup command
	FIS_REG_H2D *cmdfis = (FIS_REG_H2D*)(&cmdtbl->cfis);

	cmdfis->fis_type = FIS_TYPE_REG_H2D;
	cmdfis->c = 1;	// Command
	cmdfis->command = ATA_CMD_READ_DMA_EX;

	cmdfis->lba0 = (uint8_t)startl;
	cmdfis->lba1 = (uint8_t)(startl>>8);
	cmdfis->lba2 = (uint8_t)(startl>>16);
	cmdfis->device = 1<<6;	// LBA mode

	cmdfis->lba3 = (uint8_t)(startl>>24);
	cmdfis->lba4 = (uint8_t)starth;
	cmdfis->lba5 = (uint8_t)(starth>>8);

	cmdfis->countl = count & 0xFF;
	cmdfis->counth = (count >> 8) & 0xFF;

	// The below loop waits until the port is no longer busy before issuing a new command
	while ((port->tfd & (ATA_DEV_BUSY | ATA_DEV_DRQ)) && spin < 1000000)
	{
		spin++;
	}
	if (spin == 1000000)
	{
		kprintf_warn("Port is hung\n");
		return FALSE;
	}

	port->ci = 1<<slot;	// Issue command

	// Wait for completion
	while (1)
	{
		// In some longer duration reads, it may be helpful to spin on the DPS bit 
		// in the PxIS port field as well (1 << 5)
		if ((port->ci & (1<<slot)) == 0) 
			break;
		if (port->is & HBA_PxIS_TFES)	// Task file error
		{
			kprintf_warn("Read disk error\n");
			return FALSE;
		}
	}

	// Check again
	if (port->is & HBA_PxIS_TFES)
	{
		kprintf_warn("Read disk error\n");
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
    kprintf_warn("Cannot find free command list entry\n");
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
                (uint16_t*)buffer);
}

bool ahci_write(HBA_PORT *port, uint64_t lba, uint32_t count, void *buffer) {
    port->is = (uint32_t)-1;
    int slot = find_cmdslot(port);
    if (slot == -1)
        return false;

    HBA_CMD_HEADER *cmdheader  = (HBA_CMD_HEADER *)PHYS_TO_VIRTUAL(port->clb);
    cmdheader                 += slot;
    cmdheader->cfl             = sizeof(FIS_REG_H2D) / sizeof(uint32_t);
    cmdheader->w               = 1;
    cmdheader->prdtl           = (uint16_t)((count - 1) >> 4) + 1;

    HBA_CMD_TBL *cmdtbl = (HBA_CMD_TBL *)PHYS_TO_VIRTUAL(cmdheader->ctba);
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
        kprintf_warn("Port is hung\n");
        return FALSE;
    }

    port->ci = 1 << slot;

    while (1) {
        if ((port->ci & (1 << slot)) == 0)
            break;
        if (port->is & HBA_PxIS_TFES) {
            kprintf_warn("Write disk error\n");
            return FALSE;
        }
    }

    return TRUE;
}

pci_device_t *detect_controller() {
    pci_device_t* current = pci_devices_head;
    while (pci_devices_head) {
        const char* name_1 = pci_get_class_name(current->class_code);
        if (strcmp(name_1, "Mass Storage Controller") == 0) {
            const char* name = pci_get_subclass_name(current->class_code, current->subclass);
            if (strcmp(name, "SATA Controller") == 0) {
                return current;
            }
        }
        current = current->next;
    }
}

bool is_ahci_mode(HBA_MEM* abar) {
    if (abar->ghc & (1 << 31))
        return TRUE; // AHCI mode
    else
        return FALSE; // IDE mode
}

void test_ahci_operations(HBA_MEM *abar) {
    detect_disk(abar);

    int sata_port = get_sata_port(abar);

    char write_buffer[512] = {0}; 
    strcpy(write_buffer, "Hello from disk!");  

    ahci_write(&abar->ports[sata_port], 566, 1, write_buffer);
    char bufferf[512] = {0};
    if (ahci_read(&abar->ports[sata_port], 566, 1, bufferf)) {
        kprintf("Read successful!\n");
        kprintf("%s\n", bufferf);
    }
    else
        kprintf("Read failed!\n");
}
