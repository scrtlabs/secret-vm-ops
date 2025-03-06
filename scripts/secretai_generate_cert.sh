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
# Generates a deterministic RSA key pair and self-signed certificate
# 
# This function creates an RSA private key and certificate using a deterministic
# seed derived from system UUID. The generated files are prefixed with the provided
# prefix argument.
#
# Args:
#   prefix: String to prepend to output filenames (e.g. "myapp" creates myapp_pk.key
#          and myapp_cert.crt)
#   dest_dir: String to provide a destination location where to copy the generated
#           file to
#
# Outputs:
#   - {dest_dir}/{prefix}_pk.key: RSA private key file
#   - {dest_dir}/{prefix}_cert.crt: Self-signed X.509 certificate
#
generate_cert() {
    local prefix="$1"
    local dest_dir="${2:-.}"  # Default to current directory if not specified
    local domain="${3:-secretai.scrtlabs.com}"  # Domain name, with default
    local email="${4:-secretai@scrtlabs.com}"   # Email for Let's Encrypt notifications

    # Ensure certbot is installed
    if ! command -v certbot &> /dev/null; then
        echo "ERROR: certbot not found. Installing certbot..."
        if ! apt-get update && apt-get install -y certbot; then
            echo "ERROR: Failed to install certbot. Please install it manually."
            exit 1
        fi
    fi

    # Create directory for certificates if it doesn't exist
    mkdir -p "${dest_dir}" || { 
        echo "ERROR: Failed to create destination directory ${dest_dir}"; 
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
        exit 1
    fi
    
    # Copy the certificates to the requested location with requested prefix
    local certbot_dir="/etc/letsencrypt/live/${prefix}"
    
    sudo cp "${certbot_dir}/privkey.pem" "${dest_dir}/${prefix}_pk.key" || {
        echo "ERROR: Failed to copy private key file";
        exit 1;
    }
    
    sudo cp "${certbot_dir}/fullchain.pem" "${dest_dir}/${prefix}_cert.crt" || {
        echo "ERROR: Failed to copy certificate file";
        exit 1;
    }
    
    # Set appropriate permissions
    sudo chmod 644 "${dest_dir}/${prefix}_pk.key" || {
        echo "WARNING: Failed to set permissions on private key file";
    }
    
    sudo chmod 644 "${dest_dir}/${prefix}_cert.crt" || {
        echo "WARNING: Failed to set permissions on certificate file";
    }

    # generate ascii art banner that says: success
    if ! figlet -f slant "success" | lolcat; then
        echo "WARNING: Failed to generate success banner"
    fi

    echo "Generated: ${dest_dir}/${prefix}_pk.key and ${dest_dir}/${prefix}_cert.crt"
    echo "Let's Encrypt certificate will be valid for 90 days"
    echo "Auto-renewal is handled by the certbot timer service"
    
    # Display certificate information
    echo "Certificate details:"
    openssl x509 -noout -text -in "${dest_dir}/${prefix}_cert.crt" | grep -E "Issuer:|Subject:|Not Before:|Not After:" || {
        echo "WARNING: Failed to display certificate details";
    }
}
