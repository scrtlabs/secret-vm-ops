#!/bin/bash

# Activate Miniconda environment
source /home/claive/miniconda3/bin/activate

# ssl cert creation routines
source secretai_generate_cert.sh

#set nvidia system ready flag for confidential computing
sudo nvidia-smi conf-compute -srs 1

CERT_DIR=/mnt/secure/cert
CERT_NAME=secretai2
CERT_PATH=$CERT_DIR/"$CERT_NAME"_cert.pem
DOMAIN_NAME=tee-demo.scrtlabs.com
DOMAIN_EMAIL=info@scrtlabs.com

./startup.sh

if [ ! -e $CERT_PATH ]; then
    echo "SSL certificate not ready yet. Attempting to generate..."
    generate_cert $CERT_NAME $CERT_DIR $DOMAIN_NAME $DOMAIN_EMAIL
fi

./startup.sh finalize $CERT_PATH

