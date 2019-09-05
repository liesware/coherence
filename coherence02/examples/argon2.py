import requests
import json
import os,binascii

def sending(message):
	url = 'http://127.0.0.1:6613/'
	response=requests.post(url, data=message)
	return response.content

def argon(data_js):
	req=json.loads(data_js)
	print "Hash passwd \n " + json.dumps(req)
	data_js_n=sending(json.dumps(req))
	answ=json.loads(data_js_n)
	print "Recived Argon2 hash: \n" + (json.dumps(answ)) +"\n"
	verify= '{ "version": 1 , "algorithm":"ARGON2" ,"family":"argon2i","plaintext": "Hello world!","hex":0,"pwd":"", "operation":"verify"}';
	req=json.loads(verify)
	req["pwd"]=answ["hash"]
	req["family"]=answ["family"]
	print "Verify passwd \n " + json.dumps(req)
	data_js_n=sending(json.dumps(req))
	answ_1=json.loads(data_js_n)
	print "Recived Argon verification: \n" + (json.dumps(answ_1)) +"\n\n"

algorithms=["argon2i", "argon2d", "argon2id"]

data_js='{ "version": 1 , "algorithm":"ARGON2" ,"family":"argon2i","plaintext": "Hello world!","t_cost":10,"m_cost":16,"parallelism":4,\
"salt":"ABABABABABABABABABABABABABABABAB","hashlen":32, "hex":0, "operation":"hash"}'

argon2_js=json.loads(data_js)
for i in algorithms:
    argon2_js["family"]=i
    argon(json.dumps(argon2_js))
