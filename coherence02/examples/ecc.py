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

def ecc_pb(data_js,hash_sign):
	req=json.loads(data_js)
	curve=req["curve"]
	data_js_n=sending(json.dumps(req))
	print "Send gen : \n " + json.dumps(req) +"\n"
	answ=json.loads(data_js_n)
	print 'Recived gen: '+ json.dumps(answ)+"\n\n"
	json_enc='{ "version": 1 , "algorithm":"ECIES", "type":"string","pubkey": "" ,"operation":"enc", "plaintext":"Hello world!" }'
	req=json.loads(json_enc)
	req["pubkey"]=answ["pubkey"]
	req["curve"]=curve
	print "Send  enc: \n"+(json.dumps(req)) +"\n"
	data_js_n=sending(json.dumps(req))
	answ_1=json.loads(data_js_n)
	print "Recived  enc done: \n"+(json.dumps(answ_1)) +"\n"
	req["privkey"]=answ["privkey"]
	req["plaintext"]=answ_1["result"]
	req["pubkey"]=""
	req["operation"]="dec"
	print "Send dec : \n " + json.dumps(req) +"\n"
	data_js_n=sending(json.dumps(req))
	answ_2=json.loads(data_js_n)
	print "Recived  enc done: \n"+(json.dumps(answ_2)) +"\n\n"
	json_sign='{ "version": 1 , "algorithm":"ECDSA", "type":"string","plaintext": "Hello world!", "hex":0,"privkey": "" ,"operation":"sign"}'
	req=json.loads(json_sign)
	req["privkey"]=answ["privkey"]
	req["curve"]=curve
	req["hash_sign"]=hash_sign
	print "Send sign : \n " + json.dumps(req) +"\n"
	data_js_n=sending(json.dumps(req))
	answ_3=json.loads(data_js_n)
	print "Recived  sign done: \n"+(json.dumps(answ_3)) +"\n"
	json_verify='{ "version": 1 , "algorithm":"ECDSA", "type":"string","plaintext": "Hello world!", "hex":0,"pubkey": "", "operation":"verify","sign":""}'
	req=json.loads(json_verify)
	req["pubkey"]=answ["pubkey"]
	req["sign"]=answ_3["sign"]
	req["curve"]=curve
	req["hash_sign"]=hash_sign
	print "Send verify : \n " + json.dumps(req) +"\n"
	data_js_n=sending(json.dumps(req))
	answ_4=json.loads(data_js_n)
	print "Recived  verify done: \n"+(json.dumps(answ_4)) +"\n\n\n"
	json_sign='{ "version": 1 , "algorithm":"ECNR", "type":"string","plaintext": "Hello world!", "hex":0,"privkey": "" ,"operation":"sign"}'
	req=json.loads(json_sign)
	req["privkey"]=answ["privkey"]
	req["curve"]=curve
	req["hash_sign"]=hash_sign
	print "Send sign : \n " + json.dumps(req) +"\n"
	data_js_n=sending(json.dumps(req))
	answ_3=json.loads(data_js_n)
	print "Recived  sign done: \n"+(json.dumps(answ_3)) +"\n"
	json_verify='{ "version": 1 , "algorithm":"ECNR", "type":"string","plaintext": "Hello world!", "hex":0,"pubkey": "", "operation":"verify","sign":""}'
	req=json.loads(json_verify)
	req["pubkey"]=answ["pubkey"]
	req["sign"]=answ_3["sign"]
	req["curve"]=curve
	req["hash_sign"]=hash_sign
	print "Send verify : \n " + json.dumps(req) +"\n"
	data_js_n=sending(json.dumps(req))
	answ_4=json.loads(data_js_n)
	print "Recived  verify done: \n"+(json.dumps(answ_4)) +"\n\n\n"


def ecdh(data_js):
	req=json.loads(data_js)
	curve=req["curve"]
	print "Send gen parameters (A): \n " + json.dumps(req) +"\n"
	data_js_n=sending(json.dumps(req))
	answ=json.loads(data_js_n)
	print "Recived gen parameters donde (A): \n" + (json.dumps(answ)) +"\n\n\n"
	data_js_n=sending(json.dumps(req))
	print "Send gen parameters (B): \n " + json.dumps(req) +"\n"
	answ_1=json.loads(data_js_n)
	print "Recived gen parameters donde (B): \n" + (json.dumps(answ_1)) +"\n\n\n"
	gen='{ "version":1 , "algorithm":"ECDH","family": "", "privkey":"","sharedpub":"", "operation":"agree"}'
	req=json.loads(gen)
	req["privkey"]=answ["privkey"]
	req["sharedpub"]=answ_1["pubkey"]
	req["curve"]=curve
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


curves_bp=["brainpoolP512r1","secp521r1","brainpoolP384r1","secp384r1","brainpoolP320r1","brainpoolP256r1","secp256k1",
"sect571r1","sect571k1","sect409r1","sect409k1","sect283r1","sect283k1"]

hash_sign=["sha3_512","sha3_384","sha3_256","sha3_224","sha_512","sha_384","sha_256","sha_224","sha_1","whirlpool"]


for i in curves_bp:
	ecc_gen='{ "version": 1 , "algorithm":"ECC_GEN", "curve":"secp256k1"}'
	curv=json.loads(ecc_gen)
	curv["curve"]=i
	for j in hash_sign:
	    ecc_pb(json.dumps(curv),j)


for i in curves_bp:
	ecdh_gen='{ "version": 1 , "algorithm":"ECDH", "curve":"secp256k1", "operation":"gen"}'
	curv=json.loads(ecdh_gen)
	curv["curve"]=i
	ecdh(json.dumps(curv))
