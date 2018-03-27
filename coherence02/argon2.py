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

def argon(data_js):
	req=json.loads(data_js)
	print "Send passwd \n " + json.dumps(req) +"\n"
	data_js_n=sending(json.dumps(req))
	answ=json.loads(data_js_n)
	print "Recived argon: \n" + (json.dumps(answ)) +"\n\n\n"
	verify= '{ "version": 1 , "algorithm":"ARGON2V" ,"family":"argon2i","plaintext": "0123456789ABCDEF","hex":1,"pwd":""}';
	req=json.loads(verify)
	req["pwd"]=answ["hash"]
	print "Send passwd \n " + json.dumps(req) +"\n"
	data_js_n=sending(json.dumps(req))
	answ_1=json.loads(data_js_n)
	print "Recived argon: \n" + (json.dumps(answ_1)) +"\n\n\n"


argon2='{ "version": 1 , "algorithm":"ARGON2" ,"family":"argon2i","plaintext": "0123456789ABCDEF","t_cost":10,"m_cost":16,"parallelism":4,\
"salt":"ABABABABABABABABABABABABABABABAB","hashlen":32, "hex":1}'

argon(argon2)
