#!/bin/bash
set -x

generate_mac() {
    local first_octet="02"
    for i in {1..5}; do
        first_octet+=":$(printf "%02x" $((RANDOM % 256)))"
    done
    echo "$first_octet"
}


find_free_port() {
    for port in {2222..2300}; do
        if ! ss -tuln | grep -q ":$port\b"; then
            echo "$port"
            return
        fi
    done
    echo "No available ports 2222-2300." >&2
    exit 1
}

SSH_PORT=$(find_free_port)

create_new_img() {
    NEW_IMAGE=ubuntu-$SSH_PORT.qcow2
    if [ ! -f "/shared/images/$NEW_IMAGE" ]; then
        cp /shared/images/ubuntu-tdx-3.qcow2 /shared/images/$NEW_IMAGE
    fi
    echo $NEW_IMAGE
}

IMG=$(create_new_img)
PREFIX=/shared
OS_VER=$(lsb_release -rs)
TDX_IMG=${TDX_IMG:-${PREFIX}/images/${IMG}}
TDX_FIRMWARE=${PREFIX}/tdx-linux/edk2/OVMF.fd
PF1=80
PF2=443
PF3=30000:32767
PF4=8443:8444
MAC_ADDRESS=$(generate_mac)

if ! groups | grep -qw "kvm"; then
    echo "Permission check error. Solution: Please add user $USER to kvm group to run this script (usermod -aG kvm $USER and then log in again)."
    exit 1
fi

###################### RUN VM WITH TDX SUPPORT ##################################
PROCESS_NAME=${IMG}
LOGFILE=/tmp/${IMG}.log
# approach 1 : userspace in the guest talks to QGS (on the host) directly
available_guest_cid() {
 
    local existing_cids=$(ps aux | grep qemu | grep -o 'guest-cid=[0-9]\+' | awk -F= '{print $2}' | sort -n | uniq)
    for cid in $(seq 3 20); do
        if ! echo "$existing_cids" | grep -q "^$cid$"; then
            echo $cid
            return
        fi
    done
}
G_CID=$(available_guest_cid)
QUOTE_VSOCK_ARGS="-device vhost-vsock-pci,guest-cid=$G_CID"
# approach 2 : tdvmcall; see quote-generation-socket in qemu command line

qemu-system-x86_64 -D $LOGFILE \
		   -accel kvm \
		   -m 16G -smp 16 \
		   -name ${PROCESS_NAME},process=${PROCESS_NAME},debug-threads=on \
		   -cpu host \
		   -object '{"qom-type":"tdx-guest","id":"tdx","quote-generation-socket":{"type": "vsock", "cid":"2","port":"4050"}}' \
		   -machine q35,kernel_irqchip=split,confidential-guest-support=tdx,hpet=off \
		   -bios ${TDX_FIRMWARE} \
		   -nographic \
		   -nodefaults \
		   -device virtio-net-pci,netdev=nic0_td,mac=${MAC_ADDRESS} \
		   -netdev user,id=nic0_td,hostfwd=tcp::${SSH_PORT}-:22 \
		   -drive file=${TDX_IMG},if=none,id=virtio-disk0 \
		   -device virtio-blk-pci,drive=virtio-disk0 \
		   ${QUOTE_VSOCK_ARGS} \
		   -pidfile /tmp/${IMG}-pid.pid \
                   -daemonize \
#                   -serial stdio 
#		   -cdrom "${PREFIX}/iso/ubuntu-24.04.1-live-server-amd64.iso"

ret=$?
if [ $ret -ne 0 ]; then
	echo "Error: Failed to create TDX VM ${IMG}. Please check logfile \"$LOGFILE\" for more information."
	exit $ret
fi

PID_TD=$(cat /tmp/${IMG}-pid.pid)

echo "TDX VM started by QEMU with PID: ${PID_TD}.
To log in with the non-root user, use: $ ssh -p ${SSH_PORT} <username>@localhost
To log in as root use: $ ssh -p ${SSH_PORT} root@localhost"
