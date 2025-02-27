# Startup script

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
    # get random 32 bytes
    #local seed=$(head -c 32 /dev/random | xxd -p -c 32)
    local seed=$(./crypt_tool rand)
    if ! test_valid_hex_data "seed"; then
        return 1
    fi

    # use it to derive initial pubkey
    local pubkey=$(./crypt_tool generate-key -s $seed)
    if ! test_valid_hex_data "pubkey"; then
        return 1
    fi

    # get attestation with this pubkey as report data
    local quote=$(./attest_tool attest $pubkey)
    if ! test_valid_hex_data "quote"; then
        return 1
    fi

    local collateral=$(./dcap_collateral_tool $quote |sed -n '3p')
    if ! test_valid_hex_data "collateral"; then
        return 1
    fi

    # Query kms contract
    local kms_res=$(python3 kms_query.py 0 $quote $collateral)

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
    master_secret=$(./crypt_tool decrypt -s $seed -d $encrypted_secret -p $export_pubkey)
    if ! test_valid_hex_data "master_secret"; then
        return 1
    fi

    return 0
}

mount_secret_fs_internal()
{
    local fs_passwd="$1"
    local fs_container_path="$2"

    if [ -f $fs_container_path ]; then
        echo "Encrypted file system already exists"
        echo -n $fs_passwd | sudo cryptsetup luksOpen $fs_container_path encrypted_volume
    else
        echo "Creating encrypted file system"
        dd if=/dev/zero of=$fs_container_path bs=1M count=50
        echo -n $fs_passwd | cryptsetup luksFormat --pbkdf pbkdf2 $fs_container_path
        echo -n $fs_passwd | sudo cryptsetup luksOpen $fs_container_path encrypted_volume
        sudo mkfs.ext4 /dev/mapper/encrypted_volume
    fi

    echo "Mounting encrypted file system"
    sudo mkdir /mnt/secure
    sudo mount /dev/mapper/encrypted_volume /mnt/secure

    # to unmount:
    #   sudo umount /mnt/secure
    #   sudo rmdir /mnt/secure
    #   sudo cryptsetup luksClose encrypted_volume
}

g_Error=""

if get_master_secret; then

    mount_secret_fs_internal $master_secret "./encrypted_fs.img"
    echo "$master_secret" | sudo tee /mnt/secure/master_secret.txt > /dev/null
else
    echo "Couldn't get master secret: $g_Error"
    mount_secret_fs_internal "12345" "./encrypted_dummy.img"
fi

sudo ./attest_tool report | sudo tee /mnt/secure/self_report.txt > /dev/null
