import requests
import json
import os
import binascii

from sending import sending

def send_vmac_requests(data_js, algorithms):
    vmac_js = json.loads(data_js)
    vmac_js["key"] = binascii.b2a_hex(os.urandom(16)).decode('utf-8')
    vmac_js["iv"] = binascii.b2a_hex(os.urandom(16)).decode('utf-8')

    for algorithm in algorithms:
        vmac_js["family"] = algorithm
        response = sending(json.dumps(vmac_js))
        print(f"Received response for family {algorithm}:\n", json.dumps(json.loads(response), indent=4), "\n")

    vmac_js["hex"] = 1
    vmac_js["plaintext"] = binascii.hexlify(vmac_js["plaintext"].encode('utf-8')).decode('utf-8')

    for algorithm in algorithms:
        vmac_js["family"] = algorithm
        response = sending(json.dumps(vmac_js))
        print(f"Received response for family {algorithm} with hex encoding:\n", json.dumps(json.loads(response), indent=4), "\n")

def main():
    algorithms = ["aes", "rc6", "mars", "serpent", "twofish", "cast256"]
    data_js = '{"version":1,"algorithm":"VMAC","type":"string","plaintext":"Hello world!","hex":0,"key":"","family":"aes"}'

    send_vmac_requests(data_js, algorithms)

if __name__ == "__main__":
    main()
