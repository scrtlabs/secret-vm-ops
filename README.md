# Secret VM Operations

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A collection of operational tools and scripts for managing Secret Network virtual machines with secure attestation and cryptographic operations.

## Overview

This repository contains the operational tools required for running and managing Secret Network VMs, with a focus on:
- Secure VM startup and attestation
- SSL certificate generation and management
- Cryptographic operations
- Secure storage management

## Components

### Scripts

- `startup.sh`: Main VM startup script that handles:
  - Secure storage initialization
  - Attestation process
  - Master secret management
  - GPU attestation (when applicable)
  - SSL certificate fingerprint verification

- `secretai_generate_cert.sh`: Certificate generation script for SecretAI attestation service
  - Generates deterministic master secrets
  - Creates RSA key pairs
  - Handles Let's Encrypt certificate generation
  - Manages certificate chains and key files

### Tools

- `crypt_tool`: Cryptographic operations utility
- `attest_tool`: Attestation mechanism implementation
- Python scripts for GPU attestation and related operations

## Dependencies

### Python Requirements
```
secret-sdk==1.8.1
cryptography==44.0.2
aiohttp==3.11.13
protobuf==3.20.3
```
Full list of Python dependencies is available in `scripts/requirements.txt`

### System Requirements
- OpenSSL
- certbot (for SSL certificate generation)
- Docker (recommended for isolated environments)

## Setup and Usage

### Initial Setup

1. Install Python dependencies:
   ```bash
   cd scripts
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. Build required tools:
   ```bash
   cd crypt_tool
   cargo build --release
   ```

### VM Startup

The startup script (`startup.sh`) supports several modes of operation:

1. Standard startup:
   ```bash
   ./scripts/startup.sh
   ```

2. Finalization with SSL certificate:
   ```bash
   ./scripts/startup.sh finalize path/to/ssl/cert
   ```

3. Cleanup:
   ```bash
   ./scripts/startup.sh clear
   ```

### Certificate Generation

Generate SSL certificates for SecretAI attestation:

```bash
./scripts/secretai_generate_cert.sh [prefix] [dest_dir] [domain] [email]
```

Parameters:
- `prefix`: Prefix for generated files (default: none)
- `dest_dir`: Destination directory (default: current directory)
- `domain`: Domain name (default: secretai.scrtlabs.com)
- `email`: Contact email (default: secretai@scrtlabs.com)

## Security Considerations

1. **Master Secrets**
   - Master secrets are stored in secure storage
   - Access is restricted through filesystem encryption
   - Never exposed in plaintext

2. **Attestation**
   - TDX attestation quotes are generated securely
   - GPU attestation tokens are managed separately
   - All attestation data is stored in encrypted storage

3. **Certificate Management**
   - Private keys are protected with appropriate permissions
   - Certificate renewal is handled automatically
   - Full certificate chain is maintained

## Development

### Repository Structure

```
secret-vm-ops/
├── scripts/
│   ├── startup.sh         # Main VM startup script
│   ├── secretai_generate_cert.sh  # Certificate generation
│   └── requirements.txt   # Python dependencies
├── crypt_tool/           # Cryptographic operations tool
└── .gitignore
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a Pull Request

Please ensure all contributions:
- Follow existing code style
- Include appropriate tests
- Update documentation as needed
- Consider security implications

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

