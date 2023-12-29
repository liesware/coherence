import requests
import json
import os,binascii

from sending import sending

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

oqs_alg=["DILITHIUM","FALCON","SPHINCS+"]

dilithium_param=["dilithium2","dilithium3","dilithium5"]
falcon_param=["falcon512","falcon1024"]
sphincs_param=["shake128s","shake192s","shake256s"]


oqs_sig(oqs_alg[0],dilithium_param)
# oqs_sig(oqs_alg[1],falcon_param)
oqs_sig(oqs_alg[2],sphincs_param)

