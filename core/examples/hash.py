import requests
import json
import os
import binascii

from sending import sending

def send_hash_requests(data_js, algorithms):
    hash_js = json.loads(data_js)

    # Enviar solicitudes sin codificación hexadecimal
    for algorithm in algorithms:
        hash_js["algorithm"] = algorithm
        response = sending(json.dumps(hash_js))
        print(f"Response for algorithm {algorithm}:\n", json.dumps(json.loads(response), indent=4))

    # Enviar solicitudes con codificación hexadecimal
    hash_js["hex"] = 1
    hash_js["plaintext"] = binascii.hexlify(hash_js["plaintext"].encode('utf-8')).decode('utf-8')
    for algorithm in algorithms:
        hash_js["algorithm"] = algorithm
        response = sending(json.dumps(hash_js))
        print(f"Response for algorithm {algorithm} with hex encoding:\n", json.dumps(json.loads(response), indent=4))

def main():
    algorithms = [
        "SHA3_512", "SHA3_384", "SHA3_256", "SHA3_224",
        "SHA_512", "SHA_384", "SHA_256", "SHA_224", "SHA_1",
        "WHIRLPOOL", "BLAKE2B", "SIPHASH"
    ]
    data_js = '{"version":1,"algorithm":"SHA3_512","type":"string","plaintext":"Hello world!", "hex":0}'

    send_hash_requests(data_js, algorithms)

if __name__ == "__main__":
    main()
