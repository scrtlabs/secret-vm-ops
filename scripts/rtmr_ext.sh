#!/bin/bash

test_valid_hex384()
{
    local var_name="$1"
    local var_value="${!var_name}"

    if [[ -n "$var_value" && "$var_value" =~ ^[[:xdigit:]]+$ ]]; then
	    if [ ${#var_value} -eq 96 ]; then
        	return 0
		fi
        echo "Incorrect length (must be 48 bytes) " $var_name ": " $var_value
    else
        echo "Not a valid hex string " $var_name ": " $var_value
    fi

	exit 1
}


rtmr_prev=$1
new_val=$2

test_valid_hex384 "rtmr_prev"
test_valid_hex384 "new_val"

inp_data="${rtmr_prev}${new_val}"

out_data=$(echo -n $inp_data | xxd -r -p | openssl dgst -sha384 -binary | xxd -p -c 256)

test_valid_hex384 "out_data"

echo $out_data
