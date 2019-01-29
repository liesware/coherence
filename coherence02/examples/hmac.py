#!/usr/bin/env python

import socket
import json
import os,binascii

def sending(message):
	ip = '127.0.0.1'
	port = 6613
	BUFFER_SIZE = 65536
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((ip, port))
	s.send(message)
	print "Sending Json: \n" + message
	data = s.recv(BUFFER_SIZE)
	print  "Receiving Json: \n" + data+"\n\n"
	s.close()
	return data


algorithms=["sha3_512", "sha3_384", "sha3_256", "sha3_224", "sha_512", "sha_384", "sha_256", "sha_224", "sha_1" ,"whirlpool"]

data_js='{"version":1,"algorithm":"HMAC","type":"string","plaintext":"Hello world!","hex":0,"key":"","family":"sha3_512"}'

hmac_js=json.loads(data_js)
hmac_js["key"]=binascii.b2a_hex(os.urandom(16))
for i in algorithms :
    hmac_js["family"]=i
    sending(json.dumps(hmac_js))

hmac_js["hex"]=1
hmac_js["plaintext"]=hmac_js["plaintext"].encode("hex")
for i in algorithms :
    hmac_js["family"]=i
    sending(json.dumps(hmac_js))

data_js_f='{"version":1,"algorithm":"HMAC","type":"file","file":"./../file_test/Mayhem.txt","family":"sha3_512"}'
hmac_js=json.loads(data_js_f)
hmac_js["key"]=binascii.b2a_hex(os.urandom(16))
for i in algorithms:
    hmac_js["family"]=i
    sending(json.dumps(hmac_js))
