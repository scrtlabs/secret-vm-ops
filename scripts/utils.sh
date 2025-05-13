#!/bin/bash

set -e

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
