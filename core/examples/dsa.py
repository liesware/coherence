import requests
import json
import os,binascii

from sending import sending

def dsa(data_js, bits):
	req=json.loads(data_js)
	req["length"]=bits
	print "Send gen parameters : \n " + json.dumps(req) +"\n"
	data_js_n=sending(json.dumps(req))
	answ=json.loads(data_js_n)
	print "Recived  dsa gen: \n"+(json.dumps(answ)) +"\n\n\n"
	json_s=json_v='{ "version": 1 , "algorithm":"DSA", "type":"string","plaintext": "Hello world!", "hex":0,"privkey": "" ,"operation":"sign"}'
	req=json.loads(json_s)
	req["privkey"]=answ["privkey"]
	print "Send sign : \n " + json.dumps(req) +"\n"
	data_js_n=sending(json.dumps(req))
	answ_1=json.loads(data_js_n)
	print "Recived  sign done: \n"+(json.dumps(answ_1)) +"\n\n\n"
	json_v='{ "version": 1 , "algorithm":"DSA", "type":"string","plaintext": "Hello world!", "hex":0,"pubkey": "" ,"sign":"","operation":"verify"}'
	req=json.loads(json_v)
	req["pubkey"]=answ["pubkey"]
	req["sign"]=answ_1["sign"]
	print "Send verify : \n " + json.dumps(req) +"\n"
	data_js_n=sending(json.dumps(req))
	answ_2=json.loads(data_js_n)
	print "Recived  verify done: \n"+(json.dumps(answ_2)) +"\n\n\n"


dsa_gen='{ "version": 1 , "algorithm":"DSA", "operation":"gen", "length": 0 }'
for i in [1024,2048,3072]:
    dsa(dsa_gen,i)
