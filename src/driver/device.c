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
	struct device_info info = get_device_info(pci_addr);
	struct device device;

	if (info.class_id != 2) {
		error("Device %s is not a NIC", pci_addr);
	}
	
	if (info.vendor_id == 0x1af4 && info.device_id >= 0x1000) {
		device.is_ixgbe_device = false;
		device.dev.virtio = virtio_init(pci_addr, rx_queues, tx_queues);
		return &device.dev.virtio->ixy;
	} else {
		device.is_ixgbe_device = true;
		// Our best guess is to try ixgbe
		device.dev.ixgbe = ixgbe_init(pci_addr, rx_queues, tx_queues, interrupt_timeout);
		setup_interrupts_wrapper(device.dev.ixgbe);
		reset_and_init(device.dev.ixgbe);
		return &device.dev.ixgbe->ixy;
	}
	
}

struct device_info get_device_info(const char* pci_addr) {
	struct device_info info;
	int config = pci_open_resource(pci_addr, "config", O_RDONLY);
	info.vendor_id = read_io16(config, 0);
	info.device_id = read_io16(config, 2);
	info.class_id = read_io32(config, 8) >> 24;
	close(config);
	return info;
}