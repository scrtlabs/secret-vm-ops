#!/bin/bash

# Startup script
ATTEST_TOOL=./attest_tool
COLLATERAL_TOOL=./dcap_collateral_tool
CRYPT_TOOL=./crypt_tool

KMS_SERVICE_ID=0
SECURE_MNT=/mnt/secure
SECURE_FS_SIZE_MB=200480 # 200 GB

PATH_ATTESTATION_TDX=$SECURE_MNT/tdx_attestation.txt
PATH_ATTESTATION_GPU_1=$SECURE_MNT/gpu_attestation.txt
PATH_ATTESTATION_GPU_2=$SECURE_MNT/gpu_attestation_token.txt

# helper function, tests if a variable is a valid hex-encoded data
test_valid_hex_data()
{
    local var_name="$1"
    local var_value="${!var_name}"

    if [[ -n "$var_value" && "$var_value" =~ ^[[:xdigit:]]+$ ]]; then
        return 0
        # Valid hex
    else
        # echo "invalid value for " $var_name ": " $var_value
        g_Error=$(echo "invalid value for " $var_name ": " $var_value)
        return 1
    fi
}

# Get the master secret from kms contract, based on our attestation
get_master_secret()
{
    echo "----- Getting master secret -----"

    # get random 32 bytes
    #local seed=$(head -c 32 /dev/random | xxd -p -c 32)
    local seed=$($CRYPT_TOOL rand)
    if ! test_valid_hex_data "seed"; then
        return 1
    fi

    # use it to derive initial pubkey
    local pubkey=$($CRYPT_TOOL generate-key -s $seed)
    if ! test_valid_hex_data "pubkey"; then
        return 1
    fi

    # get attestation with this pubkey as report data
    echo "Getting initial attestation..."

    local quote=$(sudo $ATTEST_TOOL attest $pubkey)
    if ! test_valid_hex_data "quote"; then
        return 1
    fi

    local collateral=$($COLLATERAL_TOOL $quote |sed -n '3p')
    if ! test_valid_hex_data "collateral"; then
        return 1
    fi

    # Query kms contract
    echo "Querying KMS..."

    local kms_res=$(python3 kms_query.py $KMS_SERVICE_ID $quote $collateral)

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
    master_secret=$($CRYPT_TOOL decrypt -s $seed -d $encrypted_secret -p $export_pubkey)
    if ! test_valid_hex_data "master_secret"; then
        return 1
    fi

    return 0
}

mount_secret_fs()
{
    local fs_passwd="$1"
    local fs_container_path="$2"
    local size_mbs="$3"

    if [ -f $fs_container_path ]; then
        echo "Opening existing encrypted file system..."
        echo -n $fs_passwd | sudo cryptsetup luksOpen $fs_container_path encrypted_volume2
    else
        echo "Creating encrypted file system..."
        dd if=/dev/zero of=$fs_container_path bs=1M count=$size_mbs
        echo -n $fs_passwd | cryptsetup luksFormat --pbkdf pbkdf2 $fs_container_path
        echo -n $fs_passwd | sudo cryptsetup luksOpen $fs_container_path encrypted_volume2
        sudo mkfs.ext4 /dev/mapper/encrypted_volume2
    fi

    echo "Mounting encrypted file system..."
    sudo mkdir $SECURE_MNT
    sudo mount /dev/mapper/encrypted_volume2 $SECURE_MNT

    sudo chown $USER $SECURE_MNT
}

safe_remove_outdated()
{
    rm -f $PATH_ATTESTATION_GPU_1
    rm -f $PATH_ATTESTATION_GPU_2
    rm -f $PATH_ATTESTATION_TDX
}

finalize()
{
    local ssl_cert_path="$1"

    echo "Fetching fingerptint from SSL certificate..."
    local ssl_fingerprint=$(openssl x509 -in $ssl_cert_path -noout -fingerprint -sha256 | awk -F= '{gsub(":", "", $2); print $2}')

    if ! test_valid_hex_data "ssl_fingerprint"; then
        return 1
    fi

    # get random 32 bytes
    local gpu_nonce=$($CRYPT_TOOL rand)
    if ! test_valid_hex_data "gpu_nonce"; then
        return 1
    fi

    safe_remove_outdated

    python3 gpu_attest.py secret_tee $gpu_nonce $PATH_ATTESTATION_GPU_1 $PATH_ATTESTATION_GPU_2

    if [ ! -e $PATH_ATTESTATION_GPU_1 ] || [ ! -e $PATH_ATTESTATION_GPU_2 ]; then
        echo "GPU attestation not created"
        return 1
    fi

    echo "SSL certificate fingerprint: $ssl_fingerprint"
    echo "GPU attestation nonce: $gpu_nonce"

    local report_data="${ssl_fingerprint}${gpu_nonce}"

    if [ ${#report_data} -gt 128 ]; then
        g_Error=$(echo "reportdata length: ${#report_data}")
        return 1
    fi

    local quote=$(sudo $ATTEST_TOOL attest $report_data)
    if ! test_valid_hex_data "quote"; then
        return 1
    fi

    echo $quote > $PATH_ATTESTATION_TDX
    echo "TDX attestation done"

    return 0
}

g_Error=""

if [ -n "$1" ]; then
    
    if [ $1 = "finalize" ]; then

        if finalize $2; then
            echo "All done"
        else
            echo "Couldn't finalize startup: $g_Error"
        fi

    else

        if [ $1 = "clear" ]; then
            sudo umount $SECURE_MNT
            sudo rmdir $SECURE_MNT
            sudo cryptsetup luksClose encrypted_volume2

        else
            echo "Invalid argument"
        fi
    fi

else

    echo "Performing startup sequence..."

    if get_master_secret; then

	mount_secret_fs $master_secret "./encrypted_fs.img" $SECURE_FS_SIZE_MB
	echo "$master_secret" > $SECURE_MNT/master_secret.txt
    else
        echo "Couldn't get master secret: $g_Error"
        mount_secret_fs "12345" "./encrypted_dummy.img" 2
    fi

    safe_remove_outdated

    sudo $ATTEST_TOOL report > $SECURE_MNT/self_report.txt
fi

