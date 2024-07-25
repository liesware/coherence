import requests
import json
import os
import binascii

from sending import sending

def ed25519(data_js):
    req = json.loads(data_js)
    print("Send gen parameters:\n", json.dumps(req, indent=4), "\n")
    data_js_n = sending(json.dumps(req))
    answ = json.loads(data_js_n)
    print("Received ED25519 gen:\n", json.dumps(answ, indent=4), "\n\n\n")

    json_s = {
        "version": 1,
        "algorithm": "ED25519",
        "type": "string",
        "plaintext": "Hello world!",
        "hex": 0,
        "privkey": answ["privkey"],
        "operation": "sign"
    }
    print("Send sign:\n", json.dumps(json_s, indent=4), "\n")
    data_js_n = sending(json.dumps(json_s))
    answ_1 = json.loads(data_js_n)
    print("Received sign done:\n", json.dumps(answ_1, indent=4), "\n\n\n")

    json_v = {
        "version": 1,
        "algorithm": "ED25519",
        "type": "string",
        "plaintext": "Hello world!",
        "hex": 0,
        "pubkey": answ["pubkey"],
        "sign": answ_1["sign"],
        "operation": "verify"
    }
    print("Send verify:\n", json.dumps(json_v, indent=4), "\n")
    data_js_n = sending(json.dumps(json_v))
    answ_2 = json.loads(data_js_n)
    print("Received verify done:\n", json.dumps(answ_2, indent=4), "\n\n\n")

def x25519():
    x25519_gen = '{ "version": 1 , "algorithm":"X25519", "operation":"gen"}'
    req = json.loads(x25519_gen)
    print("Send gen parameters (A):\n", json.dumps(req, indent=4), "\n")
    data_js_n = sending(json.dumps(req))
    answ = json.loads(data_js_n)
    print("Received gen parameters done (A):\n", json.dumps(answ, indent=4), "\n\n\n")

    data_js_n = sending(json.dumps(req))
    print("Send gen parameters (B):\n", json.dumps(req, indent=4), "\n")
    answ_1 = json.loads(data_js_n)
    print("Received gen parameters done (B):\n", json.dumps(answ_1, indent=4), "\n\n\n")

    agree = {
        "version": 1,
        "algorithm": "X25519",
        "privkey": answ["privkey"],
        "sharedpub": answ_1["pubkey"],
        "operation": "agree"
    }
    print("Send agreement (A):\n", json.dumps(agree, indent=4), "\n")
    data_js_n = sending(json.dumps(agree))
    answ_2 = json.loads(data_js_n)
    print("Received agreement done (A):\n", json.dumps(answ_2, indent=4), "\n\n\n")

    agree["privkey"] = answ_1["privkey"]
    agree["sharedpub"] = answ["pubkey"]
    print("Send agreement (B):\n", json.dumps(agree, indent=4), "\n")
    data_js_n = sending(json.dumps(agree))
    answ_3 = json.loads(data_js_n)
    print("Received agreement done (B):\n", json.dumps(answ_3, indent=4), "\n\n\n")

def main():
    ed25519_gen = '{ "version": 1 , "algorithm":"ED25519", "operation":"gen"}'
    ed25519(ed25519_gen)
    x25519()

if __name__ == "__main__":
    main()
