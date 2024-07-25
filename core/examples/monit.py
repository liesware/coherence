import requests
import json
import os
import binascii

from sending import sending

def send_status_request(data_js):
    response = sending(data_js)
    answ = json.loads(response)
    print("Received status:\n", json.dumps(answ, indent=4), "\n")

def main():
    data_js = '{"version":1,"algorithm":"MONIT","operation":"status"}'
    send_status_request(data_js)

if __name__ == "__main__":
    main()
