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

for i in qtesla_pam:
    answ=json.loads(qesla_gen)
    answ["parameter"]=i
    data_js_n=sending(json.dumps(answ))
    answ=json.loads(data_js_n)
    print "Recived: \n" + data_js_n +"\n"
    json1=json.loads(qtesla_sign)
    json1["parameter"]=i
    json1["privkey"]=answ["privkey"]
    json1["plaintext"]=message
    data_js_n=sending(json.dumps(json1))
    answ1=json.loads(data_js_n)
    print "Recived: \n" + data_js_n +"\n"
    json2=json.loads(qtesla_v)
    json2["parameter"]=i
    json2["pubkey"]=answ["pubkey"]
    json2["plaintext"]=message
    json2["sign"]=answ1["sign"]
    data_js_n=sending(json.dumps(json2))
    answ2=json.loads(data_js_n)
    print "Recived: \n" + data_js_n +"\n"
