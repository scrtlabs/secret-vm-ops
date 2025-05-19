#!/bin/bash

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

# Read the VM unique identifier from configuration
VM_UID=$(jq -r '.vm_uid' $CONFIG_FILE)

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
    echo "Setting up env..."
    # get random 32 bytes
    SEED=$(crypt-tool rand)
    if ! test_valid_hex_data "SEED"; then
        return 1
    fi

    # get attestation with this pubkey as report data
    echo "Getting initial attestation..."

    # Derive the initial public key from the seed
    local pubkey=$(crypt-tool generate-key -s $SEED)
    if ! test_valid_hex_data "pubkey"; then
        return 1
    fi

    # Combine pubkey and VM_UID into report data
    local report_data="${pubkey}${VM_UID}"

    # Obtain TDX attestation using the combined report_data
    QUOTE=$(attest-tool attest "$report_data")
    if ! test_valid_hex_data "QUOTE"; then
        return 1
    fi

    COLLATERAL=$(curl -s -X POST https://pccs.scrtlabs.com/dcap-tools/quote-parse -H "Content-Type: application/json" -d "{\"quote\": \"$QUOTE\"}" | jq -r '.collateral')
    if ! test_valid_hex_data "COLLATERAL"; then
        return 1
    fi
    echo "Setting up env: Done."
}

setup_gpu() {
    echo "Setting up GPU..."
    nvidia-smi conf-compute -srs 1
    nvidia-ctk config --set nvidia-container-cli.no-cgroups --in-place
    echo "Setting up GPU: Done"
}

setup_docker() {
    echo "Setting up Docker..."
    systemctl stop docker.socket

    # setup docker config
    mkdir -p /etc/docker
    echo '{}' > /etc/docker/daemon.json
    test -n "$GPU_MODE" && nvidia-ctk runtime configure --runtime=docker
    jq ". + {\"data-root\": \"$SECRET_FS_MOUNT_POINT\"}" /etc/docker/daemon.json > tmp.json
    mv tmp.json /etc/docker/daemon.json

    # create docker working directory
    mkdir -p $SECRET_FS_MOUNT_POINT/docker_wd
    cp $CONFIG_DIR/docker-compose.yaml $SECRET_FS_MOUNT_POINT/docker_wd
    
    pushd .
    cd $SECRET_FS_MOUNT_POINT/docker_wd

    # Query KMS for encrypted environment variables
    local kms_env_json=$(kms-query get_env_by_image "$QUOTE" "$COLLATERAL")
    local encrypted=$(echo "$kms_env_json" | jq -r '.encrypted_secrets_plaintext // empty')
    local pubkey=$(echo "$kms_env_json"  | jq -r '.encryption_pub_key       // empty')

    # Attempt to decrypt and write to .env
    if test_valid_hex_data "encrypted" && test_valid_hex_data "pubkey"; then
        local hex_payload=$(crypt-tool decrypt -s "$SEED" -d "$encrypted" -p "$pubkey")
        if test_valid_hex_data "hex_payload"; then
            # Convert hex string to binary data
            local escaped=$(echo "$hex_payload" | sed 's/../\\x&/g')
            printf '%b' "$escaped" > .env
        else
            echo "Failed to decrypt environment variables"
        fi
    else
        echo "No environment variables provided"
        rm -f .env

    fi
    cp $CONFIG_DIR/docker-files.tar . && tar xvf ./docker-files.tar || true
    popd

    systemctl start docker.socket
    echo "Setting up Docker: Done."
}

setup_secret_fs() {
    echo "Setting up encrypted filesystem..."
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
    echo "Setting up encrypted filesystem: Done."
}

safe_remove_outdated() {
    rm -f $PATH_ATTESTATION_GPU_1
    rm -f $PATH_ATTESTATION_GPU_2
    rm -f $PATH_ATTESTATION_TDX
}

# Get the master secret from kms contract, based on our attestation
get_master_secret() {
    echo "Getting master key..."

    # Extract optional service ID from configuration
    local configured_service_id
    configured_service_id=$(jq -r '.service_id // empty' "$CONFIG_FILE")

    local kms_res
    if [ -n "$configured_service_id" ] && [ "$configured_service_id" != "null" ]; then
        # If service_id is defined, fetch secret for that service
        echo "Using service_id=$configured_service_id to fetch master secret"
        kms_res=$(kms-query get_secret_key "$configured_service_id" "$QUOTE" "$COLLATERAL")
    else
        # Otherwise, use image-based attestation to retrieve secret
        echo "No service_id in config; fetching master secret by image attestation"
        kms_res=$(kms-query get_secret_key_by_image "$QUOTE" "$COLLATERAL")
    fi

    # Extract the encrypted secret from the KMS response
    local encrypted_secret
    encrypted_secret=$(echo "$kms_res" | jq -r '.encrypted_secret_key // empty')
    if ! test_valid_hex_data "encrypted_secret"; then
        return 1
    fi

    # Extract the encryption public key from the response
    local encryption_pubkey
    encryption_pubkey=$(echo "$kms_res" | jq -r '.encryption_pub_key // empty')
    if ! test_valid_hex_data "encryption_pubkey"; then
        return 1
    fi

    # Decrypt the master secret using our seed and the returned pubkey
    MASTER_SECRET=$(crypt-tool decrypt -s "$SEED" -d "$encrypted_secret" -p "$encryption_pubkey")
    if ! test_valid_hex_data "MASTER_SECRET"; then
        return 1
    fi

    echo "Getting master key: Done."
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
    echo "Finalizing..."
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

    echo "Switching REST server to HTTPS..."
    # make secret-vm-attest-rest run https
    mkdir -p /run/systemd/system/secret-vm-attest-rest.service.d/
    cat <<EOF > /run/systemd/system/secret-vm-attest-rest.service.d/env.conf
[Service]
Environment="SECRETVM_SECURE=true"
EOF
    systemctl daemon-reload
    systemctl restart secret-vm-attest-rest
    echo "Switching REST server to HTTPS: Done."
    echo "Finalizing: Done."

    return 0
}

# ================================
#              MAIN
# ================================

# the order is crucial
test -n "$GPU_MODE" && setup_gpu
setup_env
setup_secret_fs
setup_docker

if [ ! -e $CERT_PATH ]; then
    echo "SSL certificate not ready yet. Attempting to generate..."
    generate_cert $CERT_NAME $CERT_DIR $DOMAIN_NAME $DOMAIN_EMAIL
fi

finalize $CERT_PATH
