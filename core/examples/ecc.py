import requests
import json
import os
import binascii

from sending import sending

def ecc_pb(data_js, hash_sign):
    req = json.loads(data_js)
    curve = req["curve"]
    data_js_n = sending(json.dumps(req))
    print("Send gen:\n", json.dumps(req, indent=4), "\n")
    answ = json.loads(data_js_n)
    print("Received gen:\n", json.dumps(answ, indent=4), "\n\n")

    json_enc = {
        "version": 1,
        "algorithm": "ECIES",
        "type": "string",
        "pubkey": answ["pubkey"],
        "operation": "enc",
        "plaintext": "Hello world!",
        "curve": curve
    }
    print("Send enc:\n", json.dumps(json_enc, indent=4), "\n")
    data_js_n = sending(json.dumps(json_enc))
    answ_1 = json.loads(data_js_n)
    print("Received enc done:\n", json.dumps(answ_1, indent=4), "\n")

    json_enc["privkey"] = answ["privkey"]
    json_enc["plaintext"] = answ_1["result"]
    json_enc["pubkey"] = ""
    json_enc["operation"] = "dec"
    print("Send dec:\n", json.dumps(json_enc, indent=4), "\n")
    data_js_n = sending(json.dumps(json_enc))
    answ_2 = json.loads(data_js_n)
    print("Received dec done:\n", json.dumps(answ_2, indent=4), "\n\n")

    json_sign = {
        "version": 1,
        "algorithm": "ECDSA",
        "type": "string",
        "plaintext": "Hello world!",
        "hex": 0,
        "privkey": answ["privkey"],
        "operation": "sign",
        "curve": curve,
        "hash_sign": hash_sign
    }
    print("Send sign:\n", json.dumps(json_sign, indent=4), "\n")
    data_js_n = sending(json.dumps(json_sign))
    answ_3 = json.loads(data_js_n)
    print("Received sign done:\n", json.dumps(answ_3, indent=4), "\n")

    json_verify = {
        "version": 1,
        "algorithm": "ECDSA",
        "type": "string",
        "plaintext": "Hello world!",
        "hex": 0,
        "pubkey": answ["pubkey"],
        "sign": answ_3["sign"],
        "operation": "verify",
        "curve": curve,
        "hash_sign": hash_sign
    }
    print("Send verify:\n", json.dumps(json_verify, indent=4), "\n")
    data_js_n = sending(json.dumps(json_verify))
    answ_4 = json.loads(data_js_n)
    print("Received verify done:\n", json.dumps(answ_4, indent=4), "\n\n\n")

    if curve in ["brainpoolP512r1", "secp521r1", "brainpoolP384r1", "secp384r1", "brainpoolP320r1", "brainpoolP256r1", "secp256k1"]:
        json_sign["algorithm"] = "ECNR"
        print("Send sign:\n", json.dumps(json_sign, indent=4), "\n")
        data_js_n = sending(json.dumps(json_sign))
        answ_3 = json.loads(data_js_n)
        print("Received sign done:\n", json.dumps(answ_3, indent=4), "\n")

        json_verify["algorithm"] = "ECNR"
        json_verify["sign"] = answ_3["sign"]
        print("Send verify:\n", json.dumps(json_verify, indent=4), "\n")
        data_js_n = sending(json.dumps(json_verify))
        answ_4 = json.loads(data_js_n)
        print("Received verify done:\n", json.dumps(answ_4, indent=4), "\n\n\n")

def ecdh(data_js):
    req = json.loads(data_js)
    curve = req["curve"]
    print("Send gen parameters (A):\n", json.dumps(req, indent=4), "\n")
    data_js_n = sending(json.dumps(req))
    answ = json.loads(data_js_n)
    print("Received gen parameters done (A):\n", json.dumps(answ, indent=4), "\n\n\n")

    data_js_n = sending(json.dumps(req))
    print("Send gen parameters (B):\n", json.dumps(req, indent=4), "\n")
    answ_1 = json.loads(data_js_n)
    print("Received gen parameters done (B):\n", json.dumps(answ_1, indent=4), "\n\n\n")

    gen = {
        "version": 1,
        "algorithm": "ECDH",
        "family": "",
        "privkey": answ["privkey"],
        "sharedpub": answ_1["pubkey"],
        "operation": "agree",
        "curve": curve
    }
    print("Send agreement (A):\n", json.dumps(gen, indent=4), "\n")
    data_js_n = sending(json.dumps(gen))
    answ_2 = json.loads(data_js_n)
    print("Received agreement done (A):\n", json.dumps(answ_2, indent=4), "\n\n\n")

    gen["privkey"] = answ_1["privkey"]
    gen["sharedpub"] = answ["pubkey"]
    print("Send agreement (B):\n", json.dumps(gen, indent=4), "\n")
    data_js_n = sending(json.dumps(gen))
    answ_3 = json.loads(data_js_n)
    print("Received agreement done (B):\n", json.dumps(answ_3, indent=4), "\n\n\n")

curves_bp = [
    "brainpoolP512r1", "secp521r1", "brainpoolP384r1", "secp384r1", 
    "brainpoolP320r1", "brainpoolP256r1", "secp256k1", "sect571r1", 
    "sect571k1", "sect409r1", "sect409k1", "sect283r1", "sect283k1"
]
curves_b = [
    "brainpoolP512r1", "secp521r1", "brainpoolP384r1", "secp384r1", 
    "brainpoolP320r1", "brainpoolP256r1", "secp256k1"
]

hash_sign = [
    "sha3_512", "sha3_384", "sha3_256", "sha3_224", "sha_512", 
    "sha_384", "sha_256", "sha_224", "sha_1", "whirlpool"
]

for curve in curves_b:
    ecc_gen = '{ "version": 1 , "algorithm":"ECC_GEN", "curve":"secp256k1"}'
    curv = json.loads(ecc_gen)
    curv["curve"] = curve
    for hs in hash_sign:
        ecc_pb(json.dumps(curv), hs)

for curve in curves_b:
    ecdh_gen = '{ "version": 1 , "algorithm":"ECDH", "curve":"secp256k1", "operation":"gen"}'
    curv = json.loads(ecdh_gen)
    curv["curve"] = curve
    ecdh(json.dumps(curv))
