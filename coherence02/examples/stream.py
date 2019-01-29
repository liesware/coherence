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

def stream(data_js):
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
	stream_js=json.loads(data_js)
	stream_js["key"]=binascii.b2a_hex(os.urandom(key))
	stream_js["iv"]=binascii.b2a_hex(os.urandom(iv))
	stream(json.dumps(stream_js))
	stream_js["hex"]=1
	stream_js["plaintext"]=stream_js["plaintext"].encode("hex")
	stream(json.dumps(stream_js))
	del stream_js["hex"]
	del stream_js["plaintext"]
	stream_js["type"]="file"
	stream_js["file"]="./../file_test/Mayhem.txt"
	stream(json.dumps(stream_js))

algorithms=["SOSEMANUK","SALSA20"]

data_js='{"algorithm":"SOSEMANUK","plaintext":"Hello world!","hex":0,"iv":"","version":1,"key":"","operation":"enc","type":"string"}'


stream_js=json.loads(data_js)
stream_js["algorithm"]=algorithms[0]
for i in [16,24,32]:
	common(json.dumps(stream_js),i,16)

stream_js=json.loads(data_js)
stream_js["algorithm"]=algorithms[1]
for i in [16,32]:
	common(json.dumps(stream_js),i,8)
