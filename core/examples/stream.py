import requests
import json
import os
import binascii

from sending import sending

def stream(data_js):
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
    stream_js = json.loads(data_js)
    stream_js["key"] = binascii.b2a_hex(os.urandom(key_length)).decode('utf-8')
    stream_js["iv"] = binascii.b2a_hex(os.urandom(iv_length)).decode('utf-8')
    stream(json.dumps(stream_js))
    
    stream_js["hex"] = 1
    stream_js["plaintext"] = binascii.hexlify(stream_js["plaintext"].encode('utf-8')).decode('utf-8')
    stream(json.dumps(stream_js))

def main():
    algorithms = ["SOSEMANUK", "SALSA20"]

    data_js = '{"algorithm":"SOSEMANUK","plaintext":"Hello world!","hex":0,"iv":"","version":1,"key":"","operation":"enc","type":"string"}'

    stream_js = json.loads(data_js)
    stream_js["algorithm"] = algorithms[0]
    for key_length in [16, 24, 32]:
        common(json.dumps(stream_js), key_length, 16)

    stream_js = json.loads(data_js)
    stream_js["algorithm"] = algorithms[1]
    for key_length in [16, 32]:
        common(json.dumps(stream_js), key_length, 8)

if __name__ == "__main__":
    main()
