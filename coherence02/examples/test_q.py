import requests
import json
import os,binascii

def sending(message):
	url = 'http://127.0.0.1:6613/'
	response=requests.post(url, data=message)
	return response.content

qtesla_pam=["qteslai","qteslaiiisize","qteslaiiispeed"]
message="Hello world !"
qesla_gen='{"version":1,"algorithm":"QTESLA", "operation":"gen" ,"parameter":"qteslaiiispeed"}'
qtesla_sign='{"version":1,"algorithm":"QTESLA", "operation":"sign", "type":"string" ,"parameter":"qteslaiiispeed"}'
qtesla_v='{"version":1,"algorithm":"QTESLA", "operation":"verify", "type":"string" ,"parameter":"qteslaiiispeed"}'
p=0

def gen_keys():
    answ=json.loads(qesla_gen)
    answ["parameter"]=qtesla_pam[p]
    data_js_n=sending(json.dumps(answ))
    answ=json.loads(data_js_n)
    return answ

def sign_msg(answ):
    json1=json.loads(qtesla_sign)
    json1["parameter"]=qtesla_pam[p]
    json1["privkey"]=answ["privkey"]
    json1["plaintext"]=message
    data_js_n=sending(json.dumps(json1))
    answ1=json.loads(data_js_n)
    return answ1

def very_msg(answ,answ1):
    json2=json.loads(qtesla_v)
    json2["parameter"]=qtesla_pam[p]
    json2["pubkey"]=answ["pubkey"]
    json2["plaintext"]=message
    json2["sign"]=answ1["sign"]
    data_js_n=sending(json.dumps(json2))
    answ2=json.loads(data_js_n)
    return answ2

def validate(keys):
    for i in range(1,20):
        print str(i)
        sign=sign_msg(keys)
        very=very_msg(keys,sign)
        if very["error"] != "":
            return 1
        sign["sign"]="A"*2752
        very=very_msg(keys,sign)
        if very["error"] == "":
            return 1
    return 0


while True:
    keys=gen_keys()
    sign=sign_msg(keys)
    very=very_msg(keys,sign)
    print very["error"]
    if very["error"] == "":
        status=validate(keys)
        if status == 0:
            print json.dumps(very)
            print json.dumps(keys)
            print json.dumps(sign)
            break
