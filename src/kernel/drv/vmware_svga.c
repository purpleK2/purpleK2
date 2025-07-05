/*
    Trying out PCIe with a "driver" for the VMWARE SVGA II controller
*/

#include "vmware_svga.h"

#include <pcie/pcie.h>

#include <stdio.h>

int svga2_init() {
    pcie_device_t svga2;

    if (pcie_find_device(PCI_VENDOR_ID_VMWARE, PCI_DEVICE_ID_VMWARE_SVGA2,
                         &svga2) != PCIE_STATUS_OK) {

        debugf_warn("Couldn't find a VMWare SVGA II card in this system!\n");

        return -1;
    }

    return 0;
}
