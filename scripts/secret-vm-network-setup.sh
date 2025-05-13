#!/bin/bash

set -e

CONFIG_DIR=/mnt/config
CONFIG_FILE=$CONFIG_DIR/secret-vm.json

setup_network() {
    echo "Setting up network..."
    systemctl stop systemd-networkd
    local ip_addr=$(jq -r '.ip_addr' $CONFIG_FILE)
    local gateway=$(jq -r '.gateway' $CONFIG_FILE)
    echo "IP: $ip_addr"
    echo "GATEWAY: $gateway"
    sed -i "s%IP_ADDR_PLACEHOLDER%$ip_addr%" /usr/lib/systemd/network/10-enp.network
    sed -i "s%GATEWAY_PLACEHOLDER%$gateway%" /usr/lib/systemd/network/10-enp.network
    systemctl start systemd-networkd
    echo "Setting up network: Done."
}

setup_network
