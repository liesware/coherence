from __future__ import print_function
import logging

import grpc

import coherence_pb2
import coherence_pb2_grpc

import json
import os,binascii

logging.basicConfig()

def sending(data):
    with open('ca.crt', 'rb') as f:
        creds = grpc.ssl_channel_credentials(f.read())
        channel = grpc.secure_channel('localhost:6613', creds)
        stub = coherence_pb2_grpc.coherence_offloadStub(channel)
        response = stub.coherence_js(coherence_pb2.coherence_req(req=data))
    return response.answ

def argon(data_js):
	req=json.loads(data_js)
	print ("Hash passwd \n " + json.dumps(req))
	data_js_n=sending(json.dumps(req))
	answ=json.loads(data_js_n)
	print ("Recived Argon2 hash: \n" + (json.dumps(answ)) +"\n")
	verify= '{ "version": 1 , "algorithm":"ARGON2" ,"family":"argon2i","plaintext": "Hello world!","hex":0,"pwd":"", "operation":"verify"}';
	req=json.loads(verify)
	req["pwd"]=answ["hash"]
	req["family"]=answ["family"]
	print ("Verify passwd \n " + json.dumps(req))
	data_js_n=sending(json.dumps(req))
	answ_1=json.loads(data_js_n)
	print ("Recived Argon verification: \n" + (json.dumps(answ_1)) +"\n\n")

algorithms=["argon2i", "argon2d", "argon2id"]

data_js='{ "version": 1 , "algorithm":"ARGON2" ,"family":"argon2i","plaintext": "Hello world!","t_cost":10,"m_cost":16,"parallelism":4,\
"salt":"ABABABABABABABABABABABABABABABAB","hashlen":32, "hex":0, "operation":"hash"}'

argon2_js=json.loads(data_js)
for i in algorithms:
    argon2_js["family"]=i
    argon(json.dumps(argon2_js))
