#ifndef AHCI_H
#define AHCI_H 1

#include <stdbool.h>
#include <stdint.h>
#include <util/macro.h>
#include <pci/pci.h>

#define FALSE                0
#define TRUE                 1
#define HBA_PxIS_TFES        (1 << 30)
#define SATA_SIG_ATA         0x00000101
#define SATA_SIG_ATAPI       0xEB140101
#define SATA_SIG_SEMB        0xC33C0101
#define SATA_SIG_PM          0x96690101
#define AHCI_DEV_NULL        0
#define AHCI_DEV_SATA        1
#define AHCI_DEV_SEMB        2
#define AHCI_DEV_PM          3
#define AHCI_DEV_SATAPI      4
#define HBA_PORT_IPM_ACTIVE  1
#define HBA_PORT_DET_PRESENT 3
#define ATA_CMD_READ_DMA_EX  0x25
#define HBA_PxCMD_ST         0x0001
#define HBA_PxCMD_FRE        0x0010
#define HBA_PxCMD_FR         0x4000
#define HBA_PxCMD_CR         0x8000
#define ATA_DEV_BUSY         0x80
#define ATA_DEV_DRQ          0x08
#define CMD_SLOTS            32
#define ATA_CMD_IDENTIFY     0xEC

typedef enum {
    FIS_TYPE_REG_H2D   = 0x27,
    FIS_TYPE_REG_D2H   = 0x34,
    FIS_TYPE_DMA_ACT   = 0x39,
    FIS_TYPE_DMA_SETUP = 0x41,
    FIS_TYPE_DATA      = 0x46,
    FIS_TYPE_BIST      = 0x58,
    FIS_TYPE_PIO_SETUP = 0x5F,
    FIS_TYPE_DEV_BITS  = 0xA1,
} FIS_TYPE;

typedef volatile struct tagHBA_PORT {
    uint32_t clb;
    uint32_t clbu;
    uint32_t fb;
    uint32_t fbu;
    uint32_t is;
    uint32_t ie;
    uint32_t cmd;
    uint32_t rsv0;
    uint32_t tfd;
    uint32_t sig;
    uint32_t ssts;
    uint32_t sctl;
    uint32_t serr;
    uint32_t sact;
    uint32_t ci;
    uint32_t sntf;
    uint32_t fbs;
    uint32_t rsv1[11];
    uint32_t vendor[4];
} HBA_PORT;

typedef struct tagHBA_PRDT_ENTRY {
    uint32_t dba;
    uint32_t dbau;
    uint32_t rsv0;
    uint32_t dbc : 22;
    uint32_t rsv1 : 9;
    uint32_t i : 1;
} HBA_PRDT_ENTRY;

typedef struct {
    uint8_t fis_type;
    uint8_t status;
    uint8_t error;
    uint8_t reserved0;
    uint32_t reserved1;
} PACKED FIS_DEV_BITS;

typedef struct tagFIS_REG_H2D {
    uint8_t fis_type;
    uint8_t pmport : 4;
    uint8_t rsv0 : 3;
    uint8_t c : 1;
    uint8_t command;
    uint8_t featurel;
    uint8_t lba0;
    uint8_t lba1;
    uint8_t lba2;
    uint8_t device;
    uint8_t lba3;
    uint8_t lba4;
    uint8_t lba5;
    uint8_t featureh;
    uint8_t countl;
    uint8_t counth;
    uint8_t icc;
    uint8_t control;
    uint8_t rsv1[4];
} FIS_REG_H2D;

typedef struct tagFIS_REG_D2H {
    uint8_t fis_type;
    uint8_t pmport : 4;
    uint8_t rsv0 : 2;
    uint8_t i : 1;
    uint8_t rsv1 : 1;
    uint8_t status;
    uint8_t error;
    uint8_t lba0;
    uint8_t lba1;
    uint8_t lba2;
    uint8_t device;
    uint8_t lba3;
    uint8_t lba4;
    uint8_t lba5;
    uint8_t rsv2;
    uint8_t countl;
    uint8_t counth;
    uint8_t rsv3[2];
    uint8_t rsv4[4];
} FIS_REG_D2H;

typedef struct tagFIS_DATA {
    uint8_t fis_type;
    uint8_t pmport : 4;
    uint8_t rsv0 : 4;
    uint8_t rsv1[2];
    uint32_t data[1];
} FIS_DATA;

typedef struct tagFIS_PIO_SETUP {
    uint8_t fis_type;
    uint8_t pmport : 4;
    uint8_t rsv0 : 1;
    uint8_t d : 1;
    uint8_t i : 1;
    uint8_t rsv1 : 1;
    uint8_t status;
    uint8_t error;
    uint8_t lba0;
    uint8_t lba1;
    uint8_t lba2;
    uint8_t device;
    uint8_t lba3;
    uint8_t lba4;
    uint8_t lba5;
    uint8_t rsv2;
    uint8_t countl;
    uint8_t counth;
    uint8_t rsv3;
    uint8_t e_status;
    uint16_t tc;
    uint8_t rsv4[2];
} FIS_PIO_SETUP;

typedef struct tagFIS_DMA_SETUP {
    uint8_t fis_type;
    uint8_t pmport : 4;
    uint8_t rsv0 : 1;
    uint8_t d : 1;
    uint8_t i : 1;
    uint8_t a : 1;
    uint8_t rsved[2];
    uint64_t DMAbufferID;
    uint32_t rsvd;
    uint32_t DMAbufOffset;
    uint32_t TransferCount;
    uint32_t resvd;
} FIS_DMA_SETUP;

typedef volatile struct tagHBA_MEM {
    uint32_t cap;
    uint32_t ghc;
    uint32_t is;
    uint32_t pi;
    uint32_t vs;
    uint32_t ccc_ctl;
    uint32_t ccc_pts;
    uint32_t em_loc;
    uint32_t em_ctl;
    uint32_t cap2;
    uint32_t bohc;
    uint8_t rsv[0xA0 - 0x2C];
    uint8_t vendor[0x100 - 0xA0];
    HBA_PORT ports[32];
} HBA_MEM;

typedef volatile struct tagHBA_FIS {
    FIS_DMA_SETUP dsfis;
    uint8_t pad0[4];
    FIS_PIO_SETUP psfis;
    uint8_t pad1[12];
    FIS_REG_D2H rfis;
    uint8_t pad2[4];
    FIS_DEV_BITS sdbfis;
    uint8_t ufis[64];
    uint8_t rsv[0x100 - 0xA0];
} HBA_FIS;

typedef struct tagHBA_CMD_HEADER {
    uint8_t cfl : 5;
    uint8_t a : 1;
    uint8_t w : 1;
    uint8_t p : 1;
    uint8_t r : 1;
    uint8_t b : 1;
    uint8_t c : 1;
    uint8_t rsv0 : 1;
    uint8_t pmp : 4;
    uint16_t prdtl;
    volatile uint32_t prdbc;
    uint32_t ctba;
    uint32_t ctbau;
    uint32_t rsv1[4];
} HBA_CMD_HEADER;

typedef struct tagHBA_CMD_TBL {
    uint8_t cfis[64];
    uint8_t acmd[16];
    uint8_t rsv[48];
    HBA_PRDT_ENTRY prdt_entry[1];
} HBA_CMD_TBL;

void probe_port(HBA_MEM *abar);
static int check_type(HBA_PORT *port);
void port_rebase(HBA_PORT *port);
void start_cmd(HBA_PORT *port);
void stop_cmd(HBA_PORT *port);
bool ahci_read(HBA_PORT *port, uint64_t lba, uint32_t count, void *buffer);
int find_cmdslot(HBA_PORT *port);
bool ahci_write(HBA_PORT *port, uint64_t lba, uint32_t count, void *buffer);
void detect_disk(HBA_MEM *abar);
pci_device_t *detect_controller();
int get_sata_port(HBA_MEM *abar);
bool is_ahci_mode(HBA_MEM* abar);

bool READ(HBA_PORT *port, uint32_t startl, uint32_t starth, uint32_t count, uint16_t *buf);

void test_ahci();
void test_ahci_operations(HBA_MEM *abar);

#endif // AHCI_H
