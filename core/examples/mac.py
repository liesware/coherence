import requests
import json
import os
import binascii

from sending import sending

def send_hmac_requests(data_js, algorithms):
    hmac_js = json.loads(data_js)
    hmac_js["key"] = binascii.b2a_hex(os.urandom(16)).decode('utf-8')

    for algorithm in algorithms:
        hmac_js["family"] = algorithm
        data_js_n = sending(json.dumps(hmac_js))
        answ = json.loads(data_js_n)
        print("Received Hash for algorithm", algorithm, ":\n", json.dumps(answ, indent=4), "\n")

def main():
    algorithms = ["sha3_512", "sha3_384", "sha3_256", "sha3_224", "sha_512", "sha_384", "sha_256", "sha_224", "sha_1", "whirlpool"]
    data_js = '{"version":1,"algorithm":"HMAC","type":"string","plaintext":"Hello world!","hex":0,"key":"","family":"sha3_512"}'
    
    send_hmac_requests(data_js, algorithms)

if __name__ == "__main__":
    main()
