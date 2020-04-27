from __future__ import print_function
import logging

import grpc

import coherence_pb2
import coherence_pb2_grpc

import json

def run():
    message="Hello world !"
    ed25519_gen='{ "version": 1 , "algorithm":"ED25519", "operation":"gen"}'
    ed25519_sign='{ "version": 1 , "algorithm":"ED25519", "type":"string","plaintext": "Hello world!", "hex":0,"privkey": "" ,"operation":"sign"}'
    ed25519_v='{ "version": 1 , "algorithm":"ED25519", "type":"string","plaintext": "Hello world!", "hex":0,"pubkey": "" ,"sign":"","operation":"verify"}'
    with open('ca.crt', 'rb') as f:
        creds = grpc.ssl_channel_credentials(f.read())
        channel = grpc.insecure_channel('localhost:6613')
        stub = coherence_pb2_grpc.coherence_offloadStub(channel)
        response = stub.coherence_js(coherence_pb2.coherence_req(req=ed25519_gen))
        print(response.answ)
        answ=json.loads(response.answ)
        json1=json.loads(ed25519_sign)
        json1["privkey"]=answ["privkey"]
        json1["plaintext"]=message
        response = stub.coherence_js(coherence_pb2.coherence_req(req=json.dumps(json1)))
        print(response.answ)
        answ1=json.loads(response.answ)
        json2=json.loads(ed25519_v)
        json2["pubkey"]=answ["pubkey"]
        json2["plaintext"]=message
        json2["sign"]=answ1["sign"]
        response = stub.coherence_js(coherence_pb2.coherence_req(req=json.dumps(json2)))
        print(response.answ)


if __name__ == '__main__':
    logging.basicConfig()
    run()
