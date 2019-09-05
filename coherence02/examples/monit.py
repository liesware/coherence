import requests
import json
import os,binascii

def sending(message):
	url = 'http://127.0.0.1:6613/'
	response=requests.post(url, data=message)
	return response.content


data_js='{"version":1,"algorithm":"MONIT","operation":"status"}'
sending(data_js)
