#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from nv_attestation_sdk import attestation
import json

nonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

client = attestation.Attestation()
client.set_name("secret")
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

print("NRAS Request:")
nras_request = json.dumps(data, indent=4)
print(nras_request)

print("\nNRAS Token:")
print(client.get_token())
