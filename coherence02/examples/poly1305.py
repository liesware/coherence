import requests
import json
import os,binascii

def sending(message):
	url = 'http://127.0.0.1:6613/'
	response=requests.post(url, data=message)
	return response.content

data_js='{"version":1,"algorithm":"POLY1305","type":"string","plaintext":"Hello world!","hex":0,\
"key":"","nonce":""}'
poly_js=json.loads(data_js)
poly_js["key"]=binascii.b2a_hex(os.urandom(32))
poly_js["nonce"]=binascii.b2a_hex(os.urandom(16))
sending(json.dumps(poly_js))

poly_js["hex"]=1
poly_js["plaintext"]=poly_js["plaintext"].encode("hex")
sending(json.dumps(poly_js))

del poly_js["hex"]
del poly_js["plaintext"]
poly_js["type"]="file"
poly_js["file"]="./../file_test/Mayhem.txt"
sending(json.dumps(poly_js))
