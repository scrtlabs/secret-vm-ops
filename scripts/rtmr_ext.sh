#!/bin/bash

test_valid_hex384()
{
    local var_name="$1"
    local var_value="${!var_name}"
	var_value=$(printf "%-96s" "$var_value" | tr ' ' '0')

    if [[ "$var_value" =~ ^[[:xdigit:]]+$ ]]; then
		eval "$var_name=\"\$var_value\"" # assign adjusted value back
    else
        echo "Not a valid hex string " $var_name ": " $var_value
		exit 1
    fi
}

if [ ! -n "$1" ]; then
	echo "Usage rtmr_ext [rtmr_prev] new_mesaurement"
	exit 1
fi


if [ ! -n "$2" ]; then
	rtmr_prev=""
	new_val=$1
else
	rtmr_prev=$1
	new_val=$2
fi

test_valid_hex384 "rtmr_prev"
test_valid_hex384 "new_val"

inp_data="${rtmr_prev}${new_val}"

out_data=$(echo -n $inp_data | xxd -r -p | openssl dgst -sha384 -binary | xxd -p -c 256)

test_valid_hex384 "out_data"

echo $out_data
