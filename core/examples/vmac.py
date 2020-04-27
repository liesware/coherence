import requests
import json
import os,binascii

from sending import sending

algorithms=["aes", "rc6", "mars","serpent","twofish", "cast256"]

data_js='{"version":1,"algorithm":"VMAC","type":"string","plaintext":"Hello world!","hex":0,"key":"","family":"aes"}'

vmac_js=json.loads(data_js)
vmac_js["key"]=binascii.b2a_hex(os.urandom(16))
vmac_js["iv"]=binascii.b2a_hex(os.urandom(16))
for i in algorithms :
    vmac_js["family"]=i
    sending(json.dumps(vmac_js))

vmac_js["hex"]=1
vmac_js["plaintext"]=vmac_js["plaintext"].encode("hex")
for i in algorithms :
    vmac_js["family"]=i
    sending(json.dumps(vmac_js))

# data_js_f='{"version":1,"algorithm":"VMAC","type":"file","file":"./../file_test/Mayhem.txt","family":"aes"}'
# vmac_js=json.loads(data_js_f)
# vmac_js["key"]=binascii.b2a_hex(os.urandom(16))
# vmac_js["iv"]=binascii.b2a_hex(os.urandom(16))
# for i in algorithms:
#     vmac_js["family"]=i
#     sending(json.dumps(vmac_js))
