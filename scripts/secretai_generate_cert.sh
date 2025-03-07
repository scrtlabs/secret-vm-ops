#!/bin/bash
#==============================================================================
# Name: secretai_attest.sh
# Description: Certificate generation script for SecretAI attestation service
# 
# This script performs the following operations:
# - Generates a deterministic master secret based on system UUID
# - Creates RSA private key using the master secret as seed
# - Generates Certificate Signing Request (CSR)
# - Creates self-signed certificate
#
# Usage: ./secretai_attest.sh
# Output: private.key and cert.crt in current directory
#
# Note: For production use, ensure secure master secret generation
#==============================================================================

# Generates a deterministic master secret based on system UUID
#
# This function creates a deterministic secret by hashing the system's UUID
# obtained via dmidecode. If dmidecode fails, it uses a fallback UUID value.
# The resulting hash serves as a seed for key generation.
#
# Returns:
#   SHA-256 hash of the system UUID as a hex string
#
set -ex

get_master_secret() {
    local secret_file="/mnt/secure/master_secret.txt"
    
    # Check if the file exists
    if [ -f "$secret_file" ]; then
        # Read the content of the file (trimming any whitespace)
        cat "$secret_file" | tr -d '[:space:]'
    else
        echo "Error: Master secret file not found at $secret_file" >&2
        return 1
    fi
}

# Generates a Let's Encrypt signed certificate with private and public keys
#
# This function obtains a properly signed certificate from Let's Encrypt
# using certbot in standalone mode. The generated files are prefixed with the
# provided prefix argument and saved in PEM format.
#
# Args:
#   prefix: String to prepend to output filenames (e.g. "myapp" creates myapp_private.pem, etc.)
#   dest_dir: String to provide a destination location where to copy the generated
#           files to
#   domain: Domain name for the certificate (default: secretai.scrtlabs.com)
#   email: Email address for Let's Encrypt notifications (default: secretai@scrtlabs.com)
#
# Outputs:
#   - {dest_dir}/{prefix}_private.pem: Private key file in PEM format
#p   - {dest_dir}/{prefix}_cert.pem: Let's Encrypt signed X.509 certificate in PEM format
#   - {dest_dir}/{prefix}_public.pem: Public key extracted from the certificate in PEM format
#   - {dest_dir}/{prefix}_chain.pem: Certificate chain in PEM format
#
generate_cert() {
    local prefix="$1"
    local dest_dir="${2:-.}"  # Default to current directory if not specified
    local domain="${3:-secretai.scrtlabs.com}"  # Domain name, with default
    local email="${4:-secretai@scrtlabs.com}"   # Email for Let's Encrypt notifications

    # Ensure certbot and openssl are installed
    if ! command -v certbot &> /dev/null; then
        echo "ERROR: certbot not found. Installing certbot..."
        if ! apt-get update && apt-get install -y certbot; then
            echo "ERROR: Failed to install certbot. Please install it manually."
            exit 1
        fi
    fi

    if ! command -v openssl &> /dev/null; then
        echo "ERROR: openssl not found. Installing openssl..."
        if ! apt-get update && apt-get install -y openssl; then
            echo "ERROR: Failed to install openssl. Please install it manually."
            exit 1
        fi
    fi

    # Create directory for certificates if it doesn't exist
    mkdir -p "${dest_dir}" || {
        echo "ERROR: Failed to create destination directory ${dest_dir}";
        exit 1;
    }

    # Create a temporary directory for processing files
    TEMP_DIR=$(mktemp -d) || {
        echo "ERROR: Failed to create temporary directory";
        exit 1;
    }

    echo "Requesting Let's Encrypt certificate for domain: ${domain}"

    # Request certificate using certbot in standalone mode
    if ! sudo certbot certonly --standalone \
        --non-interactive \
        --agree-tos \
        --email "${email}" \
        --domain "${domain}" \
        --cert-name "${prefix}" \
        --force-renewal; then
        echo "ERROR: Failed to obtain Let's Encrypt certificate"
        rm -rf "$TEMP_DIR"
        exit 1
    fi

    sudo chmod -R a+wr "etc/letsencrypt"
    # Certbot directory where certificates are stored
    local latest_dir=$(sudo find /etc/letsencrypt/live/ -type d -name "${prefix}*" | sort -V | tail -1)
    local certbot_dir="${latest_dir}"
    sudo chmod -R a+r ${latest_dir}
    # Copy and rename all files to the PEM format with correct naming
    sudo cp "${certbot_dir}/privkey.pem" "${dest_dir}/${prefix}_private.pem" || {
        echo "ERROR: Failed to copy private key file";
        rm -rf "$TEMP_DIR"
        exit 1;
    }

    sudo cp "${certbot_dir}/cert.pem" "${dest_dir}/${prefix}_cert.pem" || {
        echo "ERROR: Failed to copy certificate file";
        rm -rf "$TEMP_DIR"
        exit 1;
    }

    sudo cp "${certbot_dir}/chain.pem" "${dest_dir}/${prefix}_chain.pem" || {
        echo "ERROR: Failed to copy chain file";
        rm -rf "$TEMP_DIR"
        exit 1;
    }

    sudo cp "${certbot_dir}/fullchain.pem" "${dest_dir}/${prefix}_fullchain.pem" || {
        echo "ERROR: Failed to copy fullchain file";
        rm -rf "$TEMP_DIR"
        exit 1;
    }

    # Extract public key from the certificate
    if ! sudo openssl x509 -pubkey -noout -in "${certbot_dir}/cert.pem" > "${dest_dir}/${prefix}_public.pem"; then
        echo "ERROR: Failed to extract public key";
        rm -rf "$TEMP_DIR"
        exit 1;
    fi

    # Set appropriate permissions
    sudo chmod 644 "${dest_dir}/${prefix}_private.pem" || {
        echo "WARNING: Failed to set permissions on private key file";
    }

    sudo chmod 644 "${dest_dir}/${prefix}_cert.pem" "${dest_dir}/${prefix}_public.pem" \
             "${dest_dir}/${prefix}_chain.pem" "${dest_dir}/${prefix}_fullchain.pem" \
             "${dest_dir}/${prefix}_private.pem" || {
        echo "WARNING: Failed to set permissions on certificate files";
    }

    # Clean up
    rm -rf "$TEMP_DIR"

    # Generate ascii art banner that says: success
    if ! figlet -f slant "success" | lolcat; then
        echo "WARNING: Failed to generate success banner"
    fi

    echo "Generated the following PEM files in ${dest_dir}:"
    echo "- ${prefix}_private.pem (private key)"
    echo "- ${prefix}_public.pem (public key)"
    echo "- ${prefix}_cert.pem (certificate only)"
    echo "- ${prefix}_chain.pem (certificate chain without leaf cert)"
    echo "- ${prefix}_fullchain.pem (full certificate chain with leaf cert)"
    echo ""
    echo "Let's Encrypt certificate will be valid for 90 days"
    echo "Auto-renewal is handled by the certbot timer service"

    # Display certificate information
    echo "Certificate details:"
    openssl x509 -noout -text -in "${dest_dir}/${prefix}_cert.pem" | grep -E "Issuer:|Subject:|Not Before:|Not After:" || {
        echo "WARNING: Failed to display certificate details";
    }

    # Display verification information
    echo ""
    echo "To verify the private key matches the certificate:"
    echo "openssl pkey -in ${prefix}_private.pem -pubout -outform PEM | sha256sum"
    echo "openssl x509 -in ${prefix}_cert.pem -pubkey -noout -outform PEM | sha256sum"
    echo "The above commands should produce the same hash if the keys match."
}

