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
        echo "invalid value for " $var_name ": " $var_value
        exit 1
    fi
}

# Get the master secret from kms contract, based on our attestation
get_master_secret()
{
    # get random 32 bytes
    #local seed=$(head -c 32 /dev/random | xxd -p -c 32)
    local seed=$(./crypt_tool rand)
    test_valid_hex_data "seed"

    # use it to derive initial pubkey
    local pubkey=$(./crypt_tool generate-key -s $seed)
    test_valid_hex_data "pubkey"

    # get attestation with this pubkey as report data
    local quote=$(./attest_tool attest $pubkey)
    test_valid_hex_data "quote"

    local collateral=$(./dcap_collateral_tool $quote |sed -n '3p')
    test_valid_hex_data "collateral"

    # Query kms contract
    local kms_res=$(python3 kms_query.py 0 $quote $collateral)

    # the result must consist of 2 lines, which are encrypted master secret and the export pubkey respectively. Parse it.
    kms_res=$(echo "$kms_res" | xargs) # strip possible leading and trailing spaces

    read encrypted_secret export_pubkey <<< "$kms_res"
    test_valid_hex_data "encrypted_secret"
    test_valid_hex_data "export_pubkey"

    # finally decrypt the result
    local master_secret=$(./crypt_tool decrypt -s $seed -d $encrypted_secret -p $export_pubkey)
    test_valid_hex_data "master_secret"

    echo $master_secret
}

mount_secret_fs()
{
    local fs_passwd="$1"
    local fs_container_path="./encrypted_fs.img"

    if [ -f $fs_container_path ]; then
        echo "Encrypted file system already exists"
        echo -n $fs_passwd | sudo cryptsetup luksOpen $fs_container_path encrypted_volume
    else
        echo "Creating encrypted file system"
        dd if=/dev/zero of=$fs_container_path bs=1M count=500
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

#master_secret=$(get_master_secret)
#echo $master_secret

#mount_secret_fs "abracadabra"
