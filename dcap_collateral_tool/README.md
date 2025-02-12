# dcap_collateral_tool

This is our proprietary tool needed to check the DCAP quote, and fetch the latest collateral for it

## Building

Before building, make sure to install the needed TDX components:
``` bash
sudo apt install libsgx-dcap-ql libsgx-dcap-quote-verify-dev libsgx-dcap-ql-dev
```

Then the to build the tool from the source code use this command:
``` bash
g++ dcap_collateral_tool.cpp -O2 -L/usr/lib/x86_64-linux-gnu -lsgx_dcap_quoteverify -o dcap_collateral_tool
```

## Running

Usage:
``` bash
./dcap_collateral_tool <quote>
```
whereas `<quote>` should be hex-encoded DCAP quote

The tool verifies the quote, and if everything is ok - fetches the appropriate collateral, and prints it as a hex-encoded blob
