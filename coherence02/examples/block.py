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
	data = s.recv(BUFFER_SIZE)
	s.close()
	return data

def block(data_js):
	req=json.loads(data_js)
	print "Send enc \n " + json.dumps(req)
	data_js_n=sending(json.dumps(req))
	answ=json.loads(data_js_n)
	print "Recived enc: \n" + (json.dumps(answ)) +"\n"
	req["operation"]="dec"
	if req["type"]=="string":
		req["plaintext"]=answ["result"]
	if req["type"]=="file":
		req["file"]=answ["result"]
	print "Send dec \n " + json.dumps(req)
	data_js_n=sending(json.dumps(req))
	answ2=json.loads(data_js_n)
	print "Recived dec: \n" + (json.dumps(answ2)) +"\n"

def common(data_js,key,iv):
	block_js=json.loads(data_js)
	block_js["key"]=binascii.b2a_hex(os.urandom(key))
	block_js["iv"]=binascii.b2a_hex(os.urandom(iv))
	block(json.dumps(block_js))
	block_js["hex"]=1
	block_js["plaintext"]=block_js["plaintext"].encode("hex")
	block(json.dumps(block_js))
	if block_js["mode"]=="ctr":
		del block_js["hex"]
		del block_js["plaintext"]
		block_js["type"]="file"
		block_js["file"]="./../file_test/Mayhem.txt"
		block(json.dumps(block_js))


algorithms=["AES","RC6","MARS","SERPENT","TWOFISH", "CAMELLIA","CAST256","SPECK128"]
modes=["ctr","gcm"]
data_js='{"algorithm":"AES","plaintext":"Hello world!","hex":0,"iv":"","version":1,"key":"","operation":"enc","type":"string"}'

block_js=json.loads(data_js)
for i in algorithms:
    for j in [16,24,32]:
        for k in modes:
            block_js["algorithm"]=i
            block_js["mode"]=k
            if k=="gcm":
                block_js["adata"]="ABCDEF"
            common(json.dumps(block_js),j,16)


block_js=json.loads(data_js)
block_js["algorithm"]="SIMECK64"
block_js["mode"]="ctr"
common(json.dumps(block_js),16,8)
