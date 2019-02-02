import socket
import json
import os,binascii
import random

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


message="Hello world!"
oqs_gen='{"version":1,"algorithm":"", "operation":"gen" ,"parameter":""}'
oqs_sign='{"version":1,"algorithm":"", "operation":"sign", "type":"string" ,"parameter":""}'
oqs_v='{"version":1,"algorithm":"", "operation":"verify", "type":"string" ,"parameter":""}'


def oqs_sig (algorithm, params):
    for i in params:
        answ=json.loads(oqs_gen)
        answ["algorithm"]=algorithm
        answ["parameter"]=i
        print json.dumps(answ)+"Send key gen\n"
        data_js_n=sending(json.dumps(answ))
        answ=json.loads(data_js_n)
        print "Recived: \n" + data_js_n +"\n"
        json1=json.loads(oqs_sign)
        json1["algorithm"]=algorithm
        json1["parameter"]=i
        json1["privkey"]=answ["privkey"]
        json1["plaintext"]=message
        print "Send message sign\n"
        data_js_n=sending(json.dumps(json1))
        answ1=json.loads(data_js_n)
        print "Recived: \n" + data_js_n +"\n"
        json2=json.loads(oqs_v)
        json2["algorithm"]=algorithm
        json2["parameter"]=i
        json2["pubkey"]=answ["pubkey"]
        json2["plaintext"]=message
        json2["sign"]=answ1["sign"]
        print "Send message verify\n"
        data_js_n=sending(json.dumps(json2))
        answ2=json.loads(data_js_n)
        print "Recived: \n" + data_js_n +"\n"

oqs_alg=["QTESLA","DILITHIUM"]
qtesla_param=["qteslai","qteslaiiisize","qteslaiiispeed"]
dilithium_param=["dilithiumiimedium","dilithiumiiirecommended","dilithiumivveryhigh"]

oqs_sig(oqs_alg[0],qtesla_param)
oqs_sig(oqs_alg[1],dilithium_param)
