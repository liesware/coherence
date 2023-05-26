import requests
import json
import os,binascii

def sending(message):
	url = 'http://localhost:6613/'
	response=requests.post(url, data=message)
	return response.content
