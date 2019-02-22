from __future__ import print_function
import logging

import grpc

import coherence_pb2
import coherence_pb2_grpc

import json

def run():
    message="Hello world !"
    qesla_gen='{"version":1,"algorithm":"QTESLA", "operation":"gen" ,"parameter":"qteslaiiispeed"}'
    qtesla_sign='{"version":1,"algorithm":"QTESLA", "operation":"sign", "type":"string" ,"parameter":"qteslaiiispeed"}'
    qtesla_v='{"version":1,"algorithm":"QTESLA", "operation":"verify", "type":"string" ,"parameter":"qteslaiiispeed"}'
    with open('ca.crt', 'rb') as f:
        creds = grpc.ssl_channel_credentials(f.read())
        channel = grpc.secure_channel('localhost:6613', creds)
        stub = coherence_pb2_grpc.coherence_offloadStub(channel)
        response = stub.coherence_js(coherence_pb2.coherence_req(req=qesla_gen))
        print(response.answ)
        answ=json.loads(response.answ)
        json1=json.loads(qtesla_sign)
        json1["privkey"]=answ["privkey"]
        json1["plaintext"]=message
        response = stub.coherence_js(coherence_pb2.coherence_req(req=json.dumps(json1)))
        print(response.answ)
        answ1=json.loads(response.answ)
        json2=json.loads(qtesla_v)
        json2["pubkey"]=answ["pubkey"]
        json2["plaintext"]=message
        json2["sign"]=answ1["sign"]
        response = stub.coherence_js(coherence_pb2.coherence_req(req=json.dumps(json2)))
        print(response.answ)


if __name__ == '__main__':
    logging.basicConfig()
    run()
