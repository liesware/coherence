import requests
import json
import os
import binascii

from sending import sending

def argon(data_js):
    # Parse the initial JSON data
    req = json.loads(data_js)
    print("Hashing password:\n", json.dumps(req, indent=4))

    # Send the request and receive the hashed response
    data_js_n = sending(json.dumps(req))
    answ = json.loads(data_js_n)
    print("Received Argon2 hash:\n", json.dumps(answ, indent=4), "\n")

    # Prepare the verification request
    verify = {
        "version": 1,
        "algorithm": "ARGON2",
        "family": "argon2i",
        "plaintext": "Hello world!",
        "hex": 0,
        "pwd": answ["hash"],
        "operation": "verify"
    }

    print("Verifying password:\n", json.dumps(verify, indent=4))

    # Send the verification request and receive the response
    data_js_n = sending(json.dumps(verify))
    answ_1 = json.loads(data_js_n)
    print("Received Argon2 verification:\n", json.dumps(answ_1, indent=4), "\n")

def main():
    algorithms = ["argon2i", "argon2d", "argon2id"]

    data = {
        "version": 1,
        "algorithm": "ARGON2",
        "family": "argon2i",
        "plaintext": "Hello world!",
        "t_cost": 10,
        "m_cost": 16,
        "parallelism": 4,
        "salt": "ABABABABABABABABABABABABABABABAB",
        "hashlen": 32,
        "hex": 0,
        "operation": "hash"
    }

    # Process the hashing and verification for each algorithm family
    for algorithm in algorithms:
        data["family"] = algorithm
        argon(json.dumps(data))

if __name__ == "__main__":
    main()
