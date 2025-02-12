# attest_tool

This is our proprietary tool needed for TDX attestation

## Building

Before building, make sure to install the needed TDX components:
``` bash
sudo apt install libtdx-attest-dev	
```

Then the to build the tool from the source code use this command:
``` bash
gcc -O2 attest_tool.cpp -ltdx_attest -o attest_tool
```

## Running

The tool implements the following functionality:
- Getting TDX report
- Creating a TDX quote (a.k.a. attestation)
- Extending an RTMR register

**Note:** In order to run it under non-root user, the `sudo` must be used.
Or, alternatively, the user should be added to an appropriate group.

### TDX report

**Note:** this is not an attestation (a.k.a. quote). It's a diagnostic function that gets the TD measurements, but without the cryptographic proofs.

Usage:
``` bash
sudo ./attest_tool report
```

### TDX attestation

Usage:
``` bash
sudo ./attest_tool attest <report_data>
```

whereas the `<report_data>` should be hex-encoded value to be empedded into the quote, in the `REPORTDATA` field. Should be no more than 64 bytes (128 hex symbols).

### Extending RTMR register

Usage:
``` bash
sudo ./attest_tool extendrt <register> <extend_data>
```

whereas `<register>` should be the register number in range 0-3, and the `<extend_data>` should be hex-encoded value used to extend the target RTMR register.
