import requests
import json
import os,binascii

from sending import sending

oqs_gen='{"version":1,"algorithm":"","operation":"gen", "parameter":""}'
oqs_encap='{"version":1,"algorithm":"", "operation":"encap", "sharedtext":"", "pubkey":"" ,"parameter":""}'
oqs_decap='{"version":1,"algorithm":"", "operation":"decap", "type":"string" ,"parameter":""}'


def oqs_kem (algorithm, params):
    for i in params:
        answ=json.loads(oqs_gen)
        answ["algorithm"]=algorithm
        answ["parameter"]=i
        print "Send key gen\n"
        data_js_n=sending(json.dumps(answ))
        answ=json.loads(data_js_n)
        print "Recived: \n" + data_js_n +"\n"
        json1=json.loads(oqs_encap)
        json1["algorithm"]=algorithm
        json1["parameter"]=i
        json1["pubkey"]=answ["pubkey"]
        print "Send message encap"
        data_js_n=sending(json.dumps(json1))
        answ1=json.loads(data_js_n)
        print "Recived: \n" + data_js_n +"\n"
        json2=json.loads(oqs_decap)
        json2["algorithm"]=algorithm
        json2["parameter"]=i
        json2["privkey"]=answ["privkey"]
        json2["sharedtext"]=answ1["sharedtext"]
        print "Send message decap\n"
        data_js_n=sending(json.dumps(json2))
        answ2=json.loads(data_js_n)
        print "Recived: \n" + data_js_n +"\n"
        print answ1["sharedkey"]
        print answ2["sharedkey"]
        if answ1["sharedkey"] == answ2["sharedkey"]:
            print "OK (keys match)"
        else:
            print "ERROR"





kem_alg=["KYBER","SABER","NTRU_KEM"]
kyber_prm=["kyber512","kyber768","kyber1024"]
saber_prm=["light","saber","fire"]
ntru_prm=["ntru509","ntru677","ntru821","ntru701"]

oqs_kem(kem_alg[0],kyber_prm)
oqs_kem(kem_alg[1],saber_prm)
oqs_kem(kem_alg[2],ntru_prm)
