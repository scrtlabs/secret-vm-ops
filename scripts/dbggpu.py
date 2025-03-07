#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#from nv_attestation_sdk import attestation
import os
import sys
import json
import subprocess

print(sys.executable)
print(sys.path)

exit(1)

node_name = sys.argv[1]
nonce = sys.argv[2]
nras_request_path = sys.argv[3]
nras_response_path = sys.argv[4]

client = attestation.Attestation()
client.set_name(node_name)
client.set_nonce(nonce)
client.add_verifier(attestation.Devices.GPU, attestation.Environment.REMOTE, "https://nras.attestation.nvidia.com/v3/attest/gpu", "")

evidence_list = client.get_evidence()

if not client.attest(evidence_list):
    print("Attestation NOT successful")
    exit(1)

data = {
    "nonce": nonce,
    "arch": "HOPPER",
    "evidence_list": evidence_list 
}
nras_request = json.dumps(data, indent=4)

with open(nras_request_path, 'w') as file:
    file.write(nras_request)

with open(nras_response_path, 'w') as file:
    file.write(client.get_token())

