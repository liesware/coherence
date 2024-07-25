import requests
import json
import os
import binascii

from sending import sending

def process_ntru(parameter):
    ntru_gen = {
        "version": 1,
        "algorithm": "NTRU",
        "parameter": parameter,
        "operation": "gen"
    }

    data_js_n = sending(json.dumps(ntru_gen))
    answ = json.loads(data_js_n)
    print("Received gen NTRU:\n", json.dumps(answ, indent=4), "\n")

    json_enc = {
        "version": 1,
        "algorithm": "NTRU",
        "type": "string",
        "pubkey": answ["pubkey"],
        "operation": "enc",
        "plaintext": "Hello world!",
        "parameter": answ["parameter"]
    }
    data_js_n = sending(json.dumps(json_enc))
    answ_1 = json.loads(data_js_n)
    print("Received enc NTRU:\n", json.dumps(answ_1, indent=4), "\n\n\n")

    json_dec = {
        "version": 1,
        "algorithm": "NTRU",
        "type": "string",
        "privkey": answ["privkey"],
        "operation": "dec",
        "plaintext": answ_1["result"],
        "pubkey": answ["pubkey"],
        "parameter": answ["parameter"]
    }
    data_js_n = sending(json.dumps(json_dec))
    answ_2 = json.loads(data_js_n)
    print("Received dec NTRU:\n", json.dumps(answ_2, indent=4), "\n")

    json_pub = {
        "version": 1,
        "algorithm": "NTRU",
        "parameter": answ["parameter"],
        "operation": "gen_pub",
        "privkey": answ["privkey"]
    }
    data_js_n = sending(json.dumps(json_pub))
    answ_3 = json.loads(data_js_n)
    print("Received pub_gen NTRU:\n", json.dumps(answ_3, indent=4), "\n\n\n")

    json_enc["pubkey"] = answ_3["pubkey"]
    data_js_n = sending(json.dumps(json_enc))
    answ_4 = json.loads(data_js_n)
    print("Received enc NTRU:\n", json.dumps(answ_4, indent=4), "\n\n\n")

    json_dec["pubkey"] = answ_3["pubkey"]
    json_dec["plaintext"] = answ_4["result"]
    data_js_n = sending(json.dumps(json_dec))
    answ_5 = json.loads(data_js_n)
    print("Received dec NTRU:\n", json.dumps(answ_5, indent=4), "\n")

def main():
    ntru_parameters = [
        "EES449EP1", "EES613EP1", "EES761EP1", "EES677EP1", "EES887EP1",
        "EES1087EP1", "EES1087EP2", "EES1171EP1", "EES1499EP1"
    ]
    
    for parameter in ntru_parameters:
        process_ntru(parameter)

if __name__ == "__main__":
    main()
