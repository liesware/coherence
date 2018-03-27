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

def cipher(data_js, key, iv):
	req=json.loads(data_js)
	req["key"]=binascii.b2a_hex(os.urandom(key))
	req["iv"]=binascii.b2a_hex(os.urandom(iv))
	data_js_n=sending(json.dumps(req))
	answ=json.loads(data_js_n)
	req["plaintext"]=answ["result"]
	req["file"]=answ["result"]  
	req["operation"]="dec"
	data_js_f=sending(json.dumps(req))
	verify=json.loads(data_js_f)
	print 'Plain: '+ json.dumps(req) 
	print 'Encrypt: '+data_js_n
	print 'Decrypt: '+data_js_f
	print answ["result"] +' ' +verify["result"] + '\n'


data_js=['{ "version": 1 , "algorithm":"" , "type":"string", "plaintext": "616263",\
 "hex": 1, "operation":"enc","key":"","iv":""}',
'{ "version": 1 , "algorithm":"" , "type":"string", "plaintext": "Hello world", \
"hex": 0,"operation":"enc","key":"","iv":""}',
'{ "version": 1 , "algorithm":"" , "type":"string", "plaintext": "Hello world",\
"operation":"enc","key":"","iv":""}',
]

data_f=['{ "version": 1 , "algorithm":"" , "type":"file", "file": "file_test/AB.mayhem","operation":"enc","key":"","iv":"" }']

blocks=["AES","RC6","MARS","SERPENT","TWOFISH","CAST256"]

for i in data_js:
	temp_js=json.loads(i)
	temp_js["algorithm"]="SOSEMANUK"
	cipher(json.dumps(temp_js),32,16)
	temp_js["algorithm"]="SALSA20"
	cipher(json.dumps(temp_js),32,8)
	temp_js["mode"]="ctr"
	for j in blocks:
		temp_js["algorithm"]=j
		cipher(json.dumps(temp_js),32,16)
	temp_js["mode"]="gcm"
	for j in blocks:
		temp_js["adata"]=binascii.b2a_hex(os.urandom(24))
		temp_js["algorithm"]=j
		cipher(json.dumps(temp_js),32,16)	
	

for i in data_f:
	temp_js=json.loads(i)
	temp_js["algorithm"]="SOSEMANUK"
	cipher(json.dumps(temp_js),32,16)
	temp_js["algorithm"]="SALSA20"
	cipher(json.dumps(temp_js),32,8)
	temp_js["mode"]="ctr"
	for j in blocks:
		temp_js["algorithm"]=j
		cipher(json.dumps(temp_js),32,16)	
