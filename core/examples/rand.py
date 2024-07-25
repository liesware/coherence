import requests
import json
import os
import binascii

from sending import sending

def send_rand_requests(data_js, algorithms, entropy_levels):
    rand_js = json.loads(data_js)

    for entropy in entropy_levels:
        rand_js["entropy"] = entropy
        for algorithm in algorithms:
            rand_js["algorithm"] = algorithm
            response = sending(json.dumps(rand_js))
            print("Received response for algorithm", algorithm, "with entropy", entropy, ":\n", json.dumps(json.loads(response), indent=4), "\n")

def main():
    algorithms = ["RAND_RP", "RAND_AUTO", "RAND_RDRAND"]
    entropy_levels = [0, 1, 2]
    data_js = '{"version":1,"algorithm":"RAND_RP","length":12,"entropy":0}'

    send_rand_requests(data_js, algorithms, entropy_levels)

if __name__ == "__main__":
    main()
