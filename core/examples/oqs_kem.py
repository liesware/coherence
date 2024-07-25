import requests
import json
import os
import binascii

from sending import sending

oqs_gen = '{"version":1,"algorithm":"","operation":"gen", "parameter":""}'
oqs_encap = '{"version":1,"algorithm":"", "operation":"encap", "sharedtext":"", "pubkey":"", "parameter":""}'
oqs_decap = '{"version":1,"algorithm":"", "operation":"decap", "type":"string", "parameter":""}'

def oqs_kem(algorithm, params):
    for param in params:
        answ = json.loads(oqs_gen)
        answ["algorithm"] = algorithm
        answ["parameter"] = param
        print("Send key gen\n")
        data_js_n = sending(json.dumps(answ))
        answ = json.loads(data_js_n)
        print("Received:\n", json.dumps(answ, indent=4), "\n")

        json1 = json.loads(oqs_encap)
        json1["algorithm"] = algorithm
        json1["parameter"] = param
        json1["pubkey"] = answ["pubkey"]
        print("Send message encap\n")
        data_js_n = sending(json.dumps(json1))
        answ1 = json.loads(data_js_n)
        print("Received:\n", json.dumps(answ1, indent=4), "\n")

        json2 = json.loads(oqs_decap)
        json2["algorithm"] = algorithm
        json2["parameter"] = param
        json2["privkey"] = answ["privkey"]
        json2["sharedtext"] = answ1["sharedtext"]
        print("Send message decap\n")
        data_js_n = sending(json.dumps(json2))
        answ2 = json.loads(data_js_n)
        print("Received:\n", json.dumps(answ2, indent=4), "\n")

        print("Shared keys:")
        print("Encapsulation:", answ1["sharedkey"])
        print("Decapsulation:", answ2["sharedkey"])
        if answ1["sharedkey"] == answ2["sharedkey"]:
            print("OK (keys match)")
        else:
            print("ERROR")

def main():
    kem_alg = ["KYBER", "NTRU_KEM"]
    kyber_prm = ["kyber512", "kyber768", "kyber1024"]
    ntru_prm = ["sntrup761"]

    oqs_kem(kem_alg[0], kyber_prm)
    oqs_kem(kem_alg[1], ntru_prm)

if __name__ == "__main__":
    main()
