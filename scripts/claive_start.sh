#!/bin/bash

# Activate Miniconda environment
source /home/claive/miniconda3/bin/activate

# ssl cert creation routines
source secretai_generate_cert.sh

#set nvidia system ready flag for confidential computing
sudo nvidia-smi conf-compute -srs 1

CERT_DIR=/mnt/secure/cert
CERT_NAME=secretai2
CERT_PATH=$CERT_DIR/"$CERT_NAME"_cert.crt
DOMAIN_NAME=tee-demo1.scrtlabs.com
DOMAIN_EMAIL=info@scrtlabs.com

./startup.sh

if [ ! -e $CERT_PATH ]; then
    echo "SSL certificate not ready yet. Attempting to generate..."
    generate_cert $CERT_NAME $CERT_DIR $DOMAIN_NAME $DOMAIN_EMAIL
fi

./startup.sh finalize $CERT_PATH

cd /home/claive/claive_attest_rest

nohup python server.py &> server.log 
