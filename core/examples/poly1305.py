import requests
import json
import os
import binascii

from sending import sending

def send_poly1305_request(data_js):
    poly_js = json.loads(data_js)
    poly_js["key"] = binascii.b2a_hex(os.urandom(32)).decode('utf-8')
    poly_js["nonce"] = binascii.b2a_hex(os.urandom(16)).decode('utf-8')

    # Enviar solicitud sin codificación hexadecimal
    response = sending(json.dumps(poly_js))
    print("Received response:\n", json.dumps(json.loads(response), indent=4), "\n")

    # Enviar solicitud con codificación hexadecimal
    poly_js["hex"] = 1
    poly_js["plaintext"] = binascii.hexlify(poly_js["plaintext"].encode('utf-8')).decode('utf-8')
    response = sending(json.dumps(poly_js))
    print("Received response with hex encoding:\n", json.dumps(json.loads(response), indent=4), "\n")

def main():
    data_js = '{"version":1,"algorithm":"POLY1305","type":"string","plaintext":"Hello world!","hex":0, "key":"","nonce":""}'
    send_poly1305_request(data_js)

if __name__ == "__main__":
    main()
