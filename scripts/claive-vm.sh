# PREFIX="/shared/nvtrust/host_tools/sample_kvm_scripts/"
PREFIX=/shared
PROCESS_NAME="master-tdx-a"
SSH_PORT=2023
API_PORT_E=25344
API_PORT_I=11344
LLM_PORT_E=25435
LLM_PORT_I=11435
MAC_ADDRESS=9c:93:4c:b8:fc:e5
MEM_SIZE=128G
NVIDIA_DEV_ID=44:00.0

CPU_FLAGS=$(qemu-system-x86_64 -cpu help | awk '/flags/ {y=1; getline}; y {print}' | tr ' ' '\n' | grep -Ev "^$" | sed -r 's|^|+|' | tr '\n' ',' | sed -r "s|,$||")

# echo "CPU Flags: ${CPU_FLAGS}"

qemu-system-x86_64 -D claive-tdx-cc.log \
-trace enable=tdx* -D tdx_trace.log \
-initrd initramfs_rtmr3.img \
-kernel vmlinuz-6.8.0-55-generic \
-append "console=ttyS0 loglevel=7 clearcpuid=mtrr,rtmr ro" \
-bios /shared/custom/tdx-linux/edk2/OVMF-c4c99e41-574b-44b2-88f5-8ae904b6aa1b.fd \
-enable-kvm \
-name ${PROCESS_NAME},process=${PROCESS_NAME},debug-threads=on \
-drive file="claive-tdx-cc-golden.qcow2",if=virtio \
-drive file="encrypted-storage.qcow2",if=virtio \
-smp cores=16,threads=2,sockets=2 \
-m ${MEM_SIZE} \
-cpu host \
-object '{"qom-type":"tdx-guest","id":"tdx","quote-generation-socket":{"type": "vsock", "cid":"2","port":"4050"}}' \
-device virtio-net-pci,netdev=nic1_td,mac=${MAC_ADDRESS} \
-netdev tap,id=nic1_td,ifname=tap1,script=no,downscript=no \
-nographic \
-daemonize \
-object memory-backend-ram,id=mem0,size=${MEM_SIZE} \
-machine q35,kernel-irqchip=split,confidential-guest-support=tdx,hpet=off,memory-backend=mem0 \
-vga none \
-nodefaults \
-object iommufd,id=iommufd0 \
-device pcie-root-port,id=pci.1,bus=pcie.0 \
-device vhost-vsock-pci,guest-cid=10 \
-device vfio-pci,host=${NVIDIA_DEV_ID},bus=pci.1,iommufd=iommufd0 \
-fw_cfg name=opt/ovmf/X-PciMmio64,string=262144 \
-virtfs local,path=config,security_model=mapped,readonly=on,mount_tag=guest_config
#-serial stdio
#-device vfio-pci,host=${NVIDIA_DEV_ID},bus=pci.1,iommufd=iommufd0 \ 
# -cdrom "${PREFIX}/iso/ubuntu-24.04.1-live-server-amd64.iso"
#-enable-kvm
#-initrd initramfs_rtmr3.img \
#-kernel vmlinuz-6.8.0-52-generic \
#-bios /shared/custom/tdx-linux/edk2/OVMF-c4c99e41-574b-44b2-88f5-8ae904b6aa1b.fd \
