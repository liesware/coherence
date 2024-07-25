import requests
import json
import os
import binascii

from sending import sending

def rsa(data_js, bits, hash_sign):
    req = json.loads(data_js)
    req["length"] = bits
    print("Send gen parameters:\n", json.dumps(req, indent=4), "\n")
    data_js_n = sending(json.dumps(req))
    answ = json.loads(data_js_n)
    print("Received RSA gen:\n", json.dumps(answ, indent=4), "\n\n\n")

    json_s = {
        "version": 1,
        "algorithm": "RSA",
        "type": "string",
        "plaintext": "Hello world!",
        "hex": 0,
        "privkey": answ["privkey"],
        "operation": "sign",
        "hash_sign": hash_sign
    }
    print("Send sign:\n", json.dumps(json_s, indent=4), "\n")
    data_js_n = sending(json.dumps(json_s))
    answ_1 = json.loads(data_js_n)
    print("Received sign done:\n", json.dumps(answ_1, indent=4), "\n\n\n")

    json_v = {
        "version": 1,
        "algorithm": "RSA",
        "type": "string",
        "plaintext": "Hello world!",
        "hex": 0,
        "pubkey": answ["pubkey"],
        "sign": answ_1["sign"],
        "operation": "verify",
        "hash_sign": hash_sign
    }
    print("Send verify:\n", json.dumps(json_v, indent=4), "\n")
    data_js_n = sending(json.dumps(json_v))
    answ_2 = json.loads(data_js_n)
    print("Received verify done:\n", json.dumps(answ_2, indent=4), "\n\n\n")

    json_enc = {
        "version": 1,
        "algorithm": "RSA",
        "type": "string",
        "pubkey": answ["pubkey"],
        "operation": "enc",
        "plaintext": "Hello world!",
        "hex": 0
    }
    print("Send enc:\n", json.dumps(json_enc, indent=4), "\n")
    data_js_n = sending(json.dumps(json_enc))
    answ_3 = json.loads(data_js_n)
    print("Received enc done:\n", json.dumps(answ_3, indent=4), "\n\n\n")

    json_dec = {
        "version": 1,
        "algorithm": "RSA",
        "type": "string",
        "privkey": answ["privkey"],
        "operation": "dec",
        "plaintext": answ_3["result"]
    }
    print("Send dec:\n", json.dumps(json_dec, indent=4), "\n")
    data_js_n = sending(json.dumps(json_dec))
    answ_4 = json.loads(data_js_n)
    print("Received dec done:\n", json.dumps(answ_4, indent=4), "\n\n\n")

def main():
    rsa_gen = '{ "version": 1 , "algorithm":"RSA", "operation":"gen", "length": 0 }'
    hash_sign = ["sha3_512", "sha3_384", "sha3_256", "sha3_224", "sha_512", "sha_384", "sha_256", "sha_224", "sha_1", "whirlpool"]
    
    for hash_algorithm in hash_sign:
        rsa(rsa_gen, 2048, hash_algorithm)

if __name__ == "__main__":
    main()
