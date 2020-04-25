import requests
import json
import os,binascii

from sending import sending

algorithms=["sha3_512", "sha3_384", "sha3_256", "sha3_224", "sha_512", "sha_384", "sha_256", "sha_224", "sha_1" ,"whirlpool"]
data_js='{"version":1,"algorithm":"HMAC","type":"string","plaintext":"Hello world!","hex":0,"key":"","family":"sha3_512"}'

hmac_js=json.loads(data_js)
hmac_js["key"]=binascii.b2a_hex(os.urandom(16))
for i in algorithms :
    hmac_js["family"]=i
    data_js_n=sending(json.dumps(hmac_js))
    answ=json.loads(data_js_n)
    print "Recived Argon2 hash: \n" + (json.dumps(answ)) +"\n"

data_js_f='{"version":1,"algorithm":"HMAC","type":"file","file":"./../file_test/Mayhem.txt","family":"sha3_512"}'

hmac_js=json.loads(data_js_f)
hmac_js["key"]=binascii.b2a_hex(os.urandom(16))
for i in algorithms :
    hmac_js["family"]=i
    data_js_n=sending(json.dumps(hmac_js))
    answ=json.loads(data_js_n)
    print "Recived Argon2 hash: \n" + (json.dumps(answ)) +"\n"
