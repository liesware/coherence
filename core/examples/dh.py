import requests
import json
import os
import binascii

from sending import sending

def dh(data_js, bits):
    print("DH Agree with no RFC parameters")
    req = json.loads(data_js)
    req["length"] = bits
    print("Send gen parameters (A):\n", json.dumps(req, indent=4), "\n")
    data_js_n = sending(json.dumps(req))
    answ = json.loads(data_js_n)
    print("Received gen parameters done (A):\n", json.dumps(answ, indent=4), "\n\n\n")
    
    test = '{"version":1 , "algorithm":"DH","sharedpub":"","p":"","q":"","g":"", "operation":"a_n_rfc_gen"}'
    req = json.loads(test)
    req["sharedpub"] = answ["pubkey"]
    req["p"] = answ["p"]
    req["q"] = answ["q"]
    req["g"] = answ["g"]
    print("Send gen parameters from previous (B):\n", json.dumps(req, indent=4), "\n")
    data_js_n = sending(json.dumps(req))
    answ_1 = json.loads(data_js_n)
    print("Received gen parameters from previous done and agreement (B):\n", json.dumps(answ_1, indent=4), "\n\n\n")
    
    req["algorithm"] = "DH"
    req["operation"] = "a_n_rfc"
    req["sharedpub"] = answ_1["pubkey"]
    req["privkey"] = answ["privkey"]
    print("Send agreement (A):\n", json.dumps(req, indent=4), "\n")
    data_js_n = sending(json.dumps(req))
    answ_2 = json.loads(data_js_n)
    print("Received agreement done (A):\n", json.dumps(answ_2, indent=4), "\n\n\n")

def dh_1(data_js):
    req = json.loads(data_js)
    print("Send gen parameters (A):\n", json.dumps(req, indent=4), "\n")
    data_js_n = sending(json.dumps(req))
    answ = json.loads(data_js_n)
    print("Received gen parameters done (A):\n", json.dumps(answ, indent=4), "\n\n\n")
    
    req = json.loads(data_js)
    data_js_n = sending(json.dumps(req))
    print("Send gen parameters (B):\n", json.dumps(req, indent=4), "\n")
    answ_1 = json.loads(data_js_n)
    print("Received gen parameters done (B):\n", json.dumps(answ_1, indent=4), "\n\n\n")
    
    gen = '{ "version":1 , "algorithm":"DH","family": "", "privkey":"","sharedpub":"", "operation":"a_rfc"}'
    req = json.loads(gen)
    req["family"] = answ["family"]
    req["privkey"] = answ["privkey"]
    req["sharedpub"] = answ_1["pubkey"]
    print("Send agreement (A):\n", json.dumps(req, indent=4), "\n")
    data_js_n = sending(json.dumps(req))
    answ_2 = json.loads(data_js_n)
    print("Received agreement done (A):\n", json.dumps(answ_2, indent=4), "\n\n\n")
    
    req["privkey"] = answ_1["privkey"]
    req["sharedpub"] = answ["pubkey"]
    print("Send agreement (B):\n", json.dumps(req, indent=4), "\n")
    data_js_n = sending(json.dumps(req))
    answ_3 = json.loads(data_js_n)
    print("Received agreement done (B):\n", json.dumps(answ_3, indent=4), "\n\n\n")

dh_gen = '{ "version": 1 , "algorithm":"DH", "length": 512, "operation":"gen_n_rfc"}'
dh(dh_gen, 1024)

rfc = ["modp256", "modp160", "modp224"]
for i in rfc:
    dh_mod = '{ "version": 1 , "algorithm":"DH", "family": "", "operation":"gen_rfc"}'
    mods = json.loads(dh_mod)
    mods["family"] = i
    dh_1(json.dumps(mods))
