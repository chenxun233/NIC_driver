#!/usr/bin/env bash
set -euo pipefail

PCI_ADDR="${1:-0000:81:00.0}"

SYS_DEV="/sys/bus/pci/devices/${PCI_ADDR}"
[ -d "${SYS_DEV}" ] || { echo "Device ${PCI_ADDR} not found"; exit 1; }

if readlink "${SYS_DEV}/driver" | grep -qvf /dev/null <<<"vfio-pci"; then
	current_driver="$(basename "$(readlink "${SYS_DEV}/driver")")"
	echo "Unbinding ${PCI_ADDR} from ${current_driver}"
	echo "${PCI_ADDR}" > "/sys/bus/pci/drivers/${current_driver}/unbind"
else
	echo "Device already bound to vfio-pci; nothing to do."
	exit 0
fi

for module in vfio vfio_iommu_type1 vfio-pci; do
	modprobe "${module}"
done

echo "${PCI_ADDR}" > /sys/bus/pci/drivers/vfio-pci/bind

group_path="$(readlink "${SYS_DEV}/iommu_group")"
group_id="$(basename "${group_path}")"
dev_path="/dev/vfio/${group_id}"

chmod 666 /dev/vfio/vfio "${dev_path}"
echo "Bound ${PCI_ADDR} to vfio-pci and relaxed permissions on ${dev_path}"
