import requests
import json
import os,binascii

from sending import sending

algorithms=["aes", "rc6", "mars","serpent","twofish", "cast256"]

data_js='{"version":1,"algorithm":"CMAC","type":"string","plaintext":"Hello world!","hex":0,"key":"","family":"aes"}'

cmac_js=json.loads(data_js)
cmac_js["key"]=binascii.b2a_hex(os.urandom(16))
for i in algorithms :
    cmac_js["family"]=i
    sending(json.dumps(cmac_js))

cmac_js["hex"]=1
cmac_js["plaintext"]=cmac_js["plaintext"].encode("hex")
for i in algorithms :
    cmac_js["family"]=i
    sending(json.dumps(cmac_js))

data_js_f='{"version":1,"algorithm":"CMAC","type":"file","file":"./../file_test/Mayhem.txt","family":"aes"}'
cmac_js=json.loads(data_js_f)
cmac_js["key"]=binascii.b2a_hex(os.urandom(16))
for i in algorithms:
    cmac_js["family"]=i
    sending(json.dumps(cmac_js))
