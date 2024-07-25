import requests
import json
import os
import binascii

from sending import sending

def dsa(data_js, bits):
    req = json.loads(data_js)
    req["length"] = bits
    print("Send gen parameters:\n", json.dumps(req, indent=4), "\n")
    data_js_n = sending(json.dumps(req))
    answ = json.loads(data_js_n)
    print("Received DSA gen:\n", json.dumps(answ, indent=4), "\n\n\n")

    json_s = {
        "version": 1,
        "algorithm": "DSA",
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
        "algorithm": "DSA",
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

dsa_gen = '{ "version": 1 , "algorithm":"DSA", "operation":"gen", "length": 0 }'
for bits in [1024, 2048, 3072]:
    dsa(dsa_gen, bits)
