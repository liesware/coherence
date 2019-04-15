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

def ed25519(data_js):
	req=json.loads(data_js)
	print "Send gen parameters : \n " + json.dumps(req) +"\n"
	data_js_n=sending(json.dumps(req))
	answ=json.loads(data_js_n)
	print "Recived  ed25519 gen: \n"+(json.dumps(answ)) +"\n\n\n"
	json_s=json_v='{ "version": 1 , "algorithm":"ED25519", "type":"string","plaintext": "Hello world!", "hex":0,"privkey": "" ,"operation":"sign"}'
	req=json.loads(json_s)
	req["privkey"]=answ["privkey"]
	print "Send sign : \n " + json.dumps(req) +"\n"
	data_js_n=sending(json.dumps(req))
	answ_1=json.loads(data_js_n)
	print "Recived  sign done: \n"+(json.dumps(answ_1)) +"\n\n\n"
	json_v='{ "version": 1 , "algorithm":"ED25519", "type":"string","plaintext": "Hello world!", "hex":0,"pubkey": "" ,"sign":"","operation":"verify"}'
	req=json.loads(json_v)
	req["pubkey"]=answ["pubkey"]
	req["sign"]=answ_1["sign"]
	print "Send verify : \n " + json.dumps(req) +"\n"
	data_js_n=sending(json.dumps(req))
	answ_2=json.loads(data_js_n)
	print "Recived  verify done: \n"+(json.dumps(answ_2)) +"\n\n\n"


ed25519_gen='{ "version": 1 , "algorithm":"ED25519", "operation":"gen"}'
ed25519(ed25519_gen)
