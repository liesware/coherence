import requests
import json
import os,binascii

def sending(message):
	url = 'http://172.17.0.1:6613/'
	response=requests.post(url, data=message)
	return response.content
