#include <sys/file.h>

#include "device.h"
#include "driver/ixgbe.h"
#include "driver/virtio.h"
#include "pci.h"
#include "ixgbe.h"

struct ixy_device* ixy_init(const char* pci_addr, uint16_t rx_queues, uint16_t tx_queues, int interrupt_timeout) {
	// Read PCI configuration space
	// For VFIO, we could access the config space another way
	// (VFIO_PCI_CONFIG_REGION_INDEX). This is not needed, though, because
	// every config file should be world-readable, and here we
	// only read the vendor and device id.
	int config = pci_open_resource(pci_addr, "config", O_RDONLY);
	uint16_t vendor_id = read_io16(config, 0);
	uint16_t device_id = read_io16(config, 2);
	uint32_t class_id = read_io32(config, 8) >> 24;
	struct ixgbe_device* dev;
	struct virtio_device* vdev;
	close(config);
	if (class_id != 2) {
		error("Device %s is not a NIC", pci_addr);
	}
	if (vendor_id == 0x1af4 && device_id >= 0x1000) {
		vdev = virtio_init(pci_addr, rx_queues, tx_queues);
		return &vdev->ixy;
	} else {
		// Our best guess is to try ixgbe
		dev = ixgbe_init(pci_addr, rx_queues, tx_queues, interrupt_timeout);
		reset_and_init(dev);
		return &dev->ixy;
	}
	
	
}
