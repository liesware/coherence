import socket
import json
import os,binascii

def sending(message):
	ip = '127.0.0.1'
	port = 6613
	BUFFER_SIZE = 65536
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((ip, port))
	print "Sending Json: \n" + message
	s.send(message)
	data = s.recv(BUFFER_SIZE)
	print  "Receiving Json: \n" + data+"\n\n"
	s.close()
	return data

data_js='{"version":1,"algorithm":"POLY1305","type":"string","plaintext":"Hello world!","hex":0,\
"key":"","nonce":""}'
poly_js=json.loads(data_js)
poly_js["key"]=binascii.b2a_hex(os.urandom(32))
poly_js["nonce"]=binascii.b2a_hex(os.urandom(16))
sending(json.dumps(poly_js))

poly_js["hex"]=1
poly_js["plaintext"]=poly_js["plaintext"].encode("hex")
sending(json.dumps(poly_js))

del poly_js["hex"]
del poly_js["plaintext"]
poly_js["type"]="file"
poly_js["file"]="./bin/../file_test/Mayhem.txt"
sending(json.dumps(poly_js))
