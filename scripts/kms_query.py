import sys
import json
from secret_sdk.client.lcd import LCDClient

if len(sys.argv) > 3:
    svc_id = int(sys.argv[1])
    quote = list(bytearray.fromhex(sys.argv[2]))
    collateral = list(bytearray.fromhex(sys.argv[3]))

    client = LCDClient(chain_id="secretdev-1", url="http://51.8.118.178:1317")

    # Construct the query message.
    query_msg = {
        "get_secret_key": {
            "service_id": svc_id,
            "quote": quote,
            "collateral": collateral,
        }
    }

    # Query the contract.
    result = client.wasm.contract_query("secret17p5c96gksfwqtjnygrs0lghjw6n9gn6c804fdu", query_msg)

    # The response should look like this:
    # {
    #   "encrypted_secret_key": "xxxxx",
    #   "encryption_pub_key": "yyyyy"
    # }

    print(result.get('encrypted_secret_key'))
    print(result.get('encryption_pub_key'))

else:
    print(f"Usage: service_id hex_encoded(quote) hex_encoded(collateral)")
