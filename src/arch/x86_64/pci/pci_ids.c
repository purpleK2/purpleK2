#include "pci_ids.h"

#include <stdio.h>
#include <string.h>

#include <memory/heap/kheap.h>

#include <stddef.h>

// get device name string from Vendor ID and Device ID
// to avoid weird conflicts, we'll take the fio_t pointer to the pci.ids file
// @returns 0 on success
// @returns -1 if either pci_ids, vendor_out or device_out is NULL
// @returns -2 if the illegal vendor is given
int get_pcix_vendor_device_name(uint16_t vendor_id, uint16_t device_id,
                                fileio_t *pci_ids, char *vendor_out,
                                char *device_out) {
    if (!vendor_out || !device_out) {
        return -1;
    }

    if (!pci_ids) {
        debugf_warn("No pci.ids file given!\n");
        return -1;
    }

    if (vendor_id == PCIX_ILLEGAL_VENDOR) {
        return -2;
    }

    // special treatment :)
    if (vendor_id == 0x1234) {
        strcpy(vendor_out, "QEMU");
        if (device_id == 0x1111) {
            strcpy(device_out, "Emulated VGA Display Controller");
        } else if (device_id == 0x0001) {
            strcpy(device_out, "Virtio Block Device");
        } else if (device_id == 0x0002) {
            strcpy(device_out, "Virtio Network Device");
        } else {
            strcpy(device_out, UNKNOWN_DEVICE_STR);
        }

        return 0;
    }

    char *buf     = kmalloc(PCIXIDS_BUF_SIZE + 1);
    vendor_out[0] = '\0';
    device_out[0] = '\0';

    pciids_parsingmode_t parsing_mode = PCI_PARSEOTHER;
    size_t file_offset                = 0;
    size_t copy_offset                = 0;
    size_t copy_length                = 0;
    char *newline                     = NULL;

    // pci.ids parsing

    for (;;) {
        // read to buffer
        seek(pci_ids, file_offset, SEEK_SET);
        size_t bytes = read(pci_ids, PCIXIDS_BUF_SIZE, buf);
        if (!bytes) {
            // no more file to parse
            break;
        }

        buf[bytes] = '\0';

        size_t idx = 0;
        for (; idx < PCIXIDS_BUF_SIZE;) {
            char c = buf[idx];

            // analize buffer @ current index
            switch (c) {
            // '#' (comment)
            case '#':
                // skip until newline or buffer end
                while (idx < PCIXIDS_BUF_SIZE && buf[idx] != '\n') {
                    idx++;
                }
                parsing_mode = PCI_PARSEOTHER;
                break;

            // '\n' (newline)
            case '\n':
                // increment index
                if (++idx < PCIXIDS_BUF_SIZE) {
                    // suppose we are parsing a vendor and continue
                    parsing_mode = PCI_PARSEVENDOR;
                }
                continue;

            // '\t' (tab)
            case '\t':
                // if we didn't find the vendor yet
                if (!vendor_out[0]) {
                    // skip until newline or buffer end
                    while (idx < PCIXIDS_BUF_SIZE && buf[idx] != '\n') {
                        idx++;
                    }
                    parsing_mode = PCI_PARSEOTHER;
                    continue;
                }

                // if we already found the vendor, then go to parsing device
                // mode
                parsing_mode = PCI_PARSEDEVICE;

                // increment index
                if (++idx >= PCIXIDS_BUF_SIZE) {
                    continue;
                }

                break;

            // any other character:
            default:
                // if we are parsing device/vendor
                if (parsing_mode != PCI_PARSEOTHER) {
                    // go on
                    break;
                }

                // else, skip until newline or buffer end
                while (idx < PCIXIDS_BUF_SIZE && buf[idx] != '\n') {
                    idx++;
                }
                break;
            }

            // we have a device/vendor line, time to finally parse
            // parsing mode:
            switch (parsing_mode) {
            // parsing a vendor
            case PCI_PARSEVENDOR:
                if (!copy_offset) {
                    // we parse the ID only once

                    // if we have space for the buffer to check the ID
                    if (idx + 4 >= PCIXIDS_BUF_SIZE) {
                        // increment file offset (so that we start from the ID
                        // on next read)
                        idx += 4;
                        break;
                    }

                    // get the ID from the buffer
                    int id = nxatoi(&buf[idx], 4);

                    // if vendor ID doesn't match
                    if (vendor_id != id) {
                        // skip until newline or buffer end
                        while (idx < PCIXIDS_BUF_SIZE && buf[idx] != '\n') {
                            idx++;
                        }
                        parsing_mode = PCI_PARSEOTHER;
                        break;
                    }

                    // we are here because it matches
                    idx += 6;
                }

                newline     = strchr(&buf[idx], '\n');
                copy_length = newline ? (size_t)(newline - &buf[idx])
                                      : (PCIXIDS_BUF_SIZE - idx);

                // start copying
                memcpy(&vendor_out[copy_offset], &buf[idx], copy_length);

                idx += copy_length;

                // is there a newline?
                if (!newline) {
                    // we have to copy more
                    copy_offset += copy_length;
                    // done
                } else {
                    // we finished copying
                    copy_offset = 0;
                }

                break;

            // parsing a device
            case PCI_PARSEDEVICE:
                if (!copy_offset) {
                    // we parse the ID only once

                    // first, check if we aren't parsing a subvendor subdevice
                    // is this a subvendor subdevice
                    if (buf[idx] == '\t') {
                        // skip until newline or buffer end
                        while (idx < PCIXIDS_BUF_SIZE && buf[idx] != '\n') {
                            idx++;
                        }
                        break;
                    }

                    // if we have space for the buffer to check the ID
                    if (idx + 4 >= PCIXIDS_BUF_SIZE) {

                        // decrement by 4 so because
                        // idx is going to be > max buffer size
                        // we're gonna quit the for loop
                        // and file offset will be incremented by idx
                        // 3000 iq move
                        file_offset -= 4;
                        idx         += 4;
                        continue;
                    }

                    // get the ID from the buffer
                    int id = nxatoi(&buf[idx], 4);

                    // if device ID doesn't match
                    if (device_id != id) {
                        // skip until newline or buffer end
                        while (idx < PCIXIDS_BUF_SIZE && buf[idx] != '\n') {
                            idx++;
                        }
                        parsing_mode = PCI_PARSEOTHER;
                        break;
                    }

                    // we are here because it matches
                    idx += 6;
                }

                newline     = strchr(&buf[idx], '\n');
                copy_length = newline ? (size_t)(newline - &buf[idx])
                                      : (PCIXIDS_BUF_SIZE - idx);

                // start copying
                memcpy(&device_out[copy_offset], &buf[idx], copy_length);

                idx += copy_length;

                // is there a newline?
                if (!newline) {
                    // we have to copy more
                    copy_offset += copy_length;
                    // done
                } else {
                    // we finished copying
                    copy_offset = 0;
                    idx         = PCIXIDS_BUF_SIZE; // so we get out of the loop
                    break;
                }

                break;

            default:
                // skip until newline or buffer end
                while (idx < PCIXIDS_BUF_SIZE && buf[idx] != '\n') {
                    idx++;
                }
                continue;
            }
        }

        // 200 iq move
        if (device_out[0] && !copy_offset) {
            break;
        }

        // increment file offset
        file_offset += idx;
    }

    if (!vendor_out[0]) {
        // vendor wasn't likely found
        strcpy(vendor_out, UNKNOWN_VENDOR_STR);
    }

    if (!device_out[0]) {
        // same for device
        strcpy(device_out, UNKNOWN_DEVICE_STR);
    }

    kfree(buf);

    return 0;
}