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


algorithms=["aes", "rc6", "mars","serpent","twofish", "cast256"]

data_js='{"version":1,"algorithm":"CMAC","type":"string","plaintext":"Hello world!","hex":0,"key":"","family":"aes"}'

cmac_js=json.loads(data_js)
cmac_js["key"]=binascii.b2a_hex(os.urandom(16))
for i in algorithms :
    cmac_js["family"]=i
    sending(json.dumps(cmac_js))

cmac_js["hex"]=1
cmac_js["plaintext"]=cmac_js["plaintext"].encode("hex")
for i in algorithms :
    cmac_js["family"]=i
    sending(json.dumps(cmac_js))

data_js_f='{"version":1,"algorithm":"CMAC","type":"file","file":"./bin/../file_test/Mayhem.txt","family":"aes"}'
cmac_js=json.loads(data_js_f)
cmac_js["key"]=binascii.b2a_hex(os.urandom(16))
for i in algorithms:
    cmac_js["family"]=i
    sending(json.dumps(cmac_js))
