import requests
import json
import os
import binascii

from sending import sending

def block(data_js):
    req = json.loads(data_js)
    print("Send enc:\n", json.dumps(req, indent=4))
    
    data_js_n = sending(json.dumps(req))
    answ = json.loads(data_js_n)
    print("Received enc:\n", json.dumps(answ, indent=4), "\n")
    
    req["operation"] = "dec"
    if req["type"] == "string":
        req["plaintext"] = answ["result"]
    
    print("Send dec:\n", json.dumps(req, indent=4))
    
    data_js_n = sending(json.dumps(req))
    answ2 = json.loads(data_js_n)
    print("Received dec:\n", json.dumps(answ2, indent=4), "\n")

def common(data_js, key_length, iv_length):
    block_js = json.loads(data_js)
    block_js["key"] = binascii.b2a_hex(os.urandom(key_length)).decode('utf-8')
    block_js["iv"] = binascii.b2a_hex(os.urandom(iv_length)).decode('utf-8')
    
    # First run without hex encoding
    block(json.dumps(block_js))
    
    # Second run with hex encoding
    block_js["hex"] = 1
    block_js["plaintext"] = binascii.hexlify(block_js["plaintext"].encode('utf-8')).decode('utf-8')
    block(json.dumps(block_js))

def main():
    algorithms = ["AES", "RC6", "MARS", "SERPENT", "TWOFISH", "CAMELLIA", "CAST256", "SPECK128"]
    modes = ["ctr", "gcm"]
    data_js = '{"algorithm":"AES","plaintext":"Hello world!","hex":0,"iv":"","version":1,"key":"","operation":"enc","type":"string"}'
    
    block_js = json.loads(data_js)
    
    for algorithm in algorithms:
        for key_length in [16, 24, 32]:
            for mode in modes:
                block_js["algorithm"] = algorithm
                block_js["mode"] = mode
                # Uncomment if additional authenticated data (AAD) is required for GCM mode
                # if mode == "gcm":
                #     block_js["adata"] = "ABCDEF"
                common(json.dumps(block_js), key_length, 16)
    
    # Specific case for SIMECK64 with CTR mode
    block_js["algorithm"] = "SIMECK64"
    block_js["mode"] = "ctr"
    common(json.dumps(block_js), 16, 8)

if __name__ == "__main__":
    main()
