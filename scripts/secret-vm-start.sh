#!/bin/bash

set -x

# ================================
#         GLOBAL VARIABLES
# ================================

if command -v nvidia-smi; then
    GPU_MODE=1
fi

CONFIG_DIR=/mnt/config
CONFIG_FILE=$CONFIG_DIR/secret-vm.json

SECRET_FS_PERSISTENT=$(jq -r '.secret_fs_persistent' $CONFIG_FILE)
SECRET_FS_MOUNT_POINT=/mnt/secure
SECRET_FS_DEVICE=/dev/vda

CERT_DIR=$SECRET_FS_MOUNT_POINT/cert
CERT_NAME=secret_vm
CERT_PATH=$CERT_DIR/"$CERT_NAME"_cert.pem
DOMAIN_NAME=$(jq -r '.domain_name' $CONFIG_FILE)
DOMAIN_EMAIL=info@scrtlabs.com

PATH_ATTESTATION_TDX=$SECRET_FS_MOUNT_POINT/tdx_attestation.txt
PATH_ATTESTATION_GPU_1=$SECRET_FS_MOUNT_POINT/gpu_attestation.txt
PATH_ATTESTATION_GPU_2=$SECRET_FS_MOUNT_POINT/gpu_attestation_token.txt

KMS_SERVICE_ID=0

# the following variables will be set up during setup_env function call
G_ERROR=""
SEED=""
QUOTE=""
COLLATERAL=""

# ================================
#            INCLUDES
# ================================

source secret-vm-generate-cert.sh
source utils.sh

# ================================
#           FUNCTIONS
# ================================

setup_env() {
    # get random 32 bytes
    SEED=$(crypt-tool rand)
    if ! test_valid_hex_data "SEED"; then
        return 1
    fi

    # use it to derive initial pubkey
    local pubkey=$(crypt-tool generate-key -s $SEED)
    if ! test_valid_hex_data "pubkey"; then
        return 1
    fi

    # get attestation with this pubkey as report data
    echo "Getting initial attestation..."

    QUOTE=$(attest-tool attest $pubkey)
    if ! test_valid_hex_data "QUOTE"; then
        return 1
    fi

    COLLATERAL=$(curl -s -X POST https://pccs.scrtlabs.com/dcap-tools/quote-parse -H "Content-Type: application/json" -d "{\"quote\": \"$QUOTE\"}" |jq '.collateral')
    COLLATERAL=$(echo $COLLATERAL | sed 's/"//g') # remove quotes
    if ! test_valid_hex_data "COLLATERAL"; then
        return 1
    fi
}

setup_gpu() {
    nvidia-smi conf-compute -srs 1
    nvidia-ctk config --set nvidia-container-cli.no-cgroups --in-place
}

setup_docker() {
    systemctl stop docker

    # setup docker config
    mkdir -p /etc/docker
    echo '{}' > /etc/docker/daemon.json
    test -n "$GPU_MODE" && nvidia-ctk runtime configure --runtime=docker
    jq ". + {data-root: \"$SECRET_FS_MOUNT_POINT\"}" /etc/docker/daemon.json > tmp.json
    mv tmp.json /etc/docker/daemon.json

    # create docker working directory
    mkdir -p $SECRET_FS_MOUNT_POINT/docker_wd
    cp $CONFIG_DIR/docker-compose.yaml $SECRET_FS_MOUNT_POINT/docker_wd
    
    pushd .
    cd $SECRET_FS_MOUNT_POINT/docker_wd
    # these files are optional
    #local kms_res=$(kms-query get_env_by_image $QUOTE $COLLATERAL)
    cp $CONFIG_DIR/docker-files.tar . && tar xvf ./docker-files.tar || true
    popd

    systemctl start docker
}

setup_network() {
    systemctl stop systemd-networkd
    local ip_addr=$(jq -r '.ip_addr' $CONFIG_FILE)
    local gateway=$(jq -r '.gateway' $CONFIG_FILE)
    sed -i "s%IP_ADDR_PLACEHOLDER%$ip_addr%" /usr/lib/systemd/network/10-enp.network
    sed -i "s%GATEWAY_PLACEHOLDER%$gateway%" /usr/lib/systemd/network/10-enp.network
    systemctl start systemd-networkd
}

setup_secret_fs() {
    if [ "$SECRET_FS_PERSISTENT" == false ]; then
        local password=$(crypt-tool rand)
        if ! test_valid_hex_data "password"; then
            return 1
        fi
    else
        if get_master_secret; then
            local password=$MASTER_SECRET
            echo "$MASTER_SECRET" > $SECRET_FS_MOUNT_POINT/master_secret.txt
        else
            echo "Couldn't get master secret: $G_ERROR"
            exit 1
        fi
    fi

    mount_secret_fs $password $SECRET_FS_DEVICE
    safe_remove_outdated
    attest-tool report > $SECRET_FS_MOUNT_POINT/self_report.txt
}

safe_remove_outdated() {
    rm -f $PATH_ATTESTATION_GPU_1
    rm -f $PATH_ATTESTATION_GPU_2
    rm -f $PATH_ATTESTATION_TDX
}

# Get the master secret from kms contract, based on our attestation
get_master_secret() {
    # Query kms contract
    echo "Querying KMS..."

    local kms_res=$(kms-query get_secret_key $KMS_SERVICE_ID $QUOTE $COLLATERAL)

    # the result must consist of 2 lines, which are encrypted master secret and the export pubkey respectively. Parse it.
    kms_res=$(echo "$kms_res" | xargs) # strip possible leading and trailing spaces

    read encrypted_secret export_pubkey <<< "$kms_res"
    if ! test_valid_hex_data "encrypted_secret"; then
        return 1
    fi

    if ! test_valid_hex_data "export_pubkey"; then
        return 1
    fi

    # finally decrypt the result
    MASTER_SECRET=$(crypt-tool decrypt -s $SEED -d $encrypted_secret -p $export_pubkey)
    if ! test_valid_hex_data "master_secret"; then
        return 1
    fi

    return 0
}

mount_secret_fs() {
    local fs_passwd="$1"
    local fs_container_path="$2"

    echo "Opening existing encrypted file system..."
    if ! (echo -n $fs_passwd | cryptsetup luksOpen $fs_container_path encrypted_volume); then
        echo "Creating encrypted file system..."
        echo -n $fs_passwd | cryptsetup luksFormat --pbkdf pbkdf2 $fs_container_path
        echo -n $fs_passwd | cryptsetup luksOpen $fs_container_path encrypted_volume
        mkfs.ext4 /dev/mapper/encrypted_volume
    fi

    echo "Mounting encrypted file system..."
    mkdir -p $SECRET_FS_MOUNT_POINT
    mount /dev/mapper/encrypted_volume $SECRET_FS_MOUNT_POINT
}

finalize() {
    local ssl_cert_path="$1"

    echo "Fetching fingerptint from SSL certificate..."
    local ssl_fingerprint=$(openssl x509 -in $ssl_cert_path -noout -fingerprint -sha256 | awk -F= '{gsub(":", "", $2); print $2}')

    if ! test_valid_hex_data "ssl_fingerprint"; then
        return 1
    fi

    safe_remove_outdated

    echo "SSL certificate fingerprint: $ssl_fingerprint"
    local report_data="${ssl_fingerprint}"

    if [ -n "$GPU_MODE" ]; then
        # get random 32 bytes
        local gpu_nonce=$(crypt-tool rand)
        if ! test_valid_hex_data "gpu_nonce"; then
            return 1
        fi

        gpu-attest secret-vm $gpu_nonce $PATH_ATTESTATION_GPU_1 $PATH_ATTESTATION_GPU_2

        if [ ! -e $PATH_ATTESTATION_GPU_1 ] || [ ! -e $PATH_ATTESTATION_GPU_2 ]; then
            echo "GPU attestation not created"
            return 1
        fi
        echo "GPU attestation nonce: $gpu_nonce"
        report_data="${report_data}${gpu_nonce}"
    fi

    if [ ${#report_data} -gt 128 ]; then
        G_ERROR=$(echo "reportdata length: ${#report_data}")
        return 1
    fi

    local quote=$(attest-tool attest $report_data)
    if ! test_valid_hex_data "quote"; then
        return 1
    fi

    echo $quote > $PATH_ATTESTATION_TDX
    echo "TDX attestation done"

    return 0
}

# ================================
#              MAIN
# ================================

# the order is crucial
setup_network
test -n "$GPU_MODE" && setup_gpu
setup_env
setup_secret_fs
setup_docker

if [ ! -e $CERT_PATH ]; then
    echo "SSL certificate not ready yet. Attempting to generate..."
    generate_cert $CERT_NAME $CERT_DIR $DOMAIN_NAME $DOMAIN_EMAIL
fi

finalize $CERT_PATH
