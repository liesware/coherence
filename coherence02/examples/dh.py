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

def dh(data_js, bits):
	print "DH Agree with no RFC  parameters"
	req=json.loads(data_js)
	req["length"]=bits
	print "Send gen parameters (A): \n " + json.dumps(req) +"\n"
	data_js_n=sending(json.dumps(req))
	answ=json.loads(data_js_n)
	print "Recived gen parameters donde (A): \n" + (json.dumps(answ)) +"\n\n\n"
	test='{"version":1 , "algorithm":"DH","sharedpub":"","p":"","q":"","g":"", "operation":"a_n_rfc_gen"}';
	req=json.loads(test)
	req["sharedpub"]=answ["pubkey"]
	req["p"]=answ["p"]
	req["q"]=answ["q"]
	req["g"]=answ["g"]
	print "Send gen parameters from previous (B): \n" + json.dumps(req) +"\n"
	data_js_n=sending(json.dumps(req))
	answ_1=json.loads(data_js_n)
	print "Recived gen parameters from previous done and agreetment (B): \n"+ (json.dumps(answ_1)) +"\n\n\n"
	req["algorithm"]="DH"
	req["operation"]="a_n_rfc"
	req["sharedpub"]=answ_1["pubkey"]
	req["privkey"]=answ["privkey"]
	print "Send agreetment (A): \n" + json.dumps(req) +"\n"
	data_js_n=sending(json.dumps(req))
	answ_2=json.loads(data_js_n)
	print "Recived agreetment done (A): \n"+ (json.dumps(answ_2)) +"\n\n\n"

def dh_1(data_js):
	req=json.loads(data_js)
	print "Send gen parameters (A): \n " + json.dumps(req) +"\n"
	data_js_n=sending(json.dumps(req))
	answ=json.loads(data_js_n)
	print "Recived gen parameters donde (A): \n" + (json.dumps(answ)) +"\n\n\n"
	data_js_n=sending(json.dumps(req))
	print "Send gen parameters (B): \n " + json.dumps(req) +"\n"
	answ_1=json.loads(data_js_n)
	print "Recived gen parameters donde (B): \n" + (json.dumps(answ_1)) +"\n\n\n"
	gen='{ "version":1 , "algorithm":"DH","family": "", "privkey":"","sharedpub":"", "operation":"a_rfc"}'
	req=json.loads(gen)
	req["family"]=answ["family"]
	req["privkey"]=answ["privkey"]
	req["sharedpub"]=answ_1["pubkey"]
	print "Send agreetment (A): \n " + json.dumps(req) +"\n"
	data_js_n=sending(json.dumps(req))
	answ_2=json.loads(data_js_n)
	print "Recived agreetment donde (A): \n" + (json.dumps(answ_2)) +"\n\n\n"
	req["privkey"]=answ_1["privkey"]
	req["sharedpub"]=answ["pubkey"]
	print "Send agreetment (B): \n " + json.dumps(req) +"\n"
	data_js_n=sending(json.dumps(req))
	answ_3=json.loads(data_js_n)
	print "Recived agreetment donde (B): \n" + (json.dumps(answ_3)) +"\n\n\n"


dh_gen='{ "version": 1 , "algorithm":"DH", "length": 512, "operation":"gen_n_rfc"}'
dh(dh_gen,1024)

rfc=["modp256","modp160","modp224"]
for i in rfc:
	dh_mod='{ "version": 1 , "algorithm":"DH", "family": "", "operation":"gen_rfc"}'
	mods=json.loads(dh_mod)
	mods["family"]=i
	dh_1(json.dumps(mods))
