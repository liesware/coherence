import requests
import json
import os,binascii

def sending(message):
	url = 'http://127.0.0.1:6613/'
	response=requests.post(url, data=message)
	return response.content

algorithms=["RAND_RP", "RAND_AUTO", "RAND_RDRAND"]
entropy=[0,1,2]
data_js='{"version":1,"algorithm":"RAND_RP","length":12, "entropy": 0}'


rand_js=json.loads(data_js)
for i in entropy:
    rand_js["entropy"]=i
    for j in algorithms:
        rand_js["algorithm"]=j
        sending(json.dumps(rand_js))
