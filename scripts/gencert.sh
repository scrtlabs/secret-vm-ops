#!/bin/bash
#
# Import SSL certificate generation and management functions
set -ex
source secretai_generate_cert.sh

# Name of the certificate used for SSL/TLS encryption
CERT_NAME="secretai2"

# Directory path where SSL certificates will be stored
CERT_DIR="/mnt/secure/cert"
mkdir -p ${CERT_DIR}

DOMAIN_NAME="tee-demo2.scrtlabs.com"

DOMAIN_EMAIL="secretai@scrtlabs.com"

# Generates SSL certificates for secure communication
# Defined in: secretai_generate_cert.sh
# Args:
#   $1: Certificate name (e.g. "secretai")
#   $2: Directory path to store certificates
# Returns: 0 on success, 1 on failure
if ! generate_cert "$CERT_NAME" "$CERT_DIR" "$DOMAIN_NAME" "$DOMAIN_EMAIL" ; then
    echo "ERROR: Failed to generate certificates"
    exit 1
fi
