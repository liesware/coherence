import requests
import json
import os,binascii

from sending import sending

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


def x25519():
	x25519_gen='{ "version": 1 , "algorithm":"X25519", "operation":"gen"}'
	req=json.loads(x25519_gen)
	print "Send gen parameters (A): \n " + json.dumps(req) +"\n"
	data_js_n=sending(json.dumps(req))
	answ=json.loads(data_js_n)
	print "Recived gen parameters donde (A): \n" + (json.dumps(answ)) +"\n\n\n"
	data_js_n=sending(json.dumps(req))
	print "Send gen parameters (B): \n " + json.dumps(req) +"\n"
	answ_1=json.loads(data_js_n)
	print "Recived gen parameters donde (B): \n" + (json.dumps(answ_1)) +"\n\n\n"
	agree='{ "version":1 , "algorithm":"X25519", "privkey":"","sharedpub":"", "operation":"agree"}'
	req=json.loads(agree)
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



ed25519_gen='{ "version": 1 , "algorithm":"ED25519", "operation":"gen"}'
ed25519(ed25519_gen)

x25519()
