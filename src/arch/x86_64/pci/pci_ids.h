#ifndef PCI_IDS_H
#define PCI_IDS_H 1

#include <fs/file_io.h>

#include <stdint.h>

#define PCIX_ILLEGAL_VENDOR 0xFFFF
#define PCIX_ILLEGAL_DEVICE 0xFFFF

#define UNKNOWN_VENDOR_STR "*Unknown vendor*"
#define UNKNOWN_DEVICE_STR "*Unknown device*"

#define PCIXIDS_BUF_SIZE 32

#define PCI_ID_LEN      4
#define PCI_DEVICE_SKIP 6 // 4 digits + 2 spaces
#define PCI_SUBDEV_SKIP 7 // tab + 4 digits + 2 spaces

typedef enum pciids_parsing_mode {
    PCI_PARSEVENDOR,
    PCI_PARSEDEVICE,
    PCI_PARSEOTHER
} pciids_parsingmode_t;

int get_pcix_vendor_device_name(uint16_t vendor_id, uint16_t device_id,
                                fileio_t *pci_ids, char *vendor_out,
                                char *device_out);

#endif