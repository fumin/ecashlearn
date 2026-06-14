import json

with open("../wallet/wallet.json") as f:
    b = f.read()
formatted = json.dumps(json.loads(b), indent=4)
print(formatted)
