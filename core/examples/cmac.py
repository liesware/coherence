import requests
import json
import os
import binascii

from sending import sending

def send_cmac_request(data_js):
    cmac_js = json.loads(data_js)
    cmac_js["key"] = binascii.b2a_hex(os.urandom(16)).decode('utf-8')
    
    algorithms = ["aes", "rc6", "mars", "serpent", "twofish", "cast256"]
    
    for algorithm in algorithms:
        cmac_js["family"] = algorithm
        response = sending(json.dumps(cmac_js))
        print("Response for family", algorithm, ":\n", json.dumps(json.loads(response), indent=4))
    
    cmac_js["hex"] = 1
    cmac_js["plaintext"] = binascii.hexlify(cmac_js["plaintext"].encode('utf-8')).decode('utf-8')
    
    for algorithm in algorithms:
        cmac_js["family"] = algorithm
        response = sending(json.dumps(cmac_js))
        print("Response for family", algorithm, "with hex encoding:\n", json.dumps(json.loads(response), indent=4))

def main():
    data_js = '{"version":1,"algorithm":"CMAC","type":"string","plaintext":"Hello world!","hex":0,"key":"","family":"aes"}'
    send_cmac_request(data_js)

if __name__ == "__main__":
    main()
