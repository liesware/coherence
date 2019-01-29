#!/usr/bin/env python

import socket
import json
import os,binascii

def sending(message):
	ip = '127.0.0.1'
	port = 6613
	BUFFER_SIZE = 65536
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((ip, port))
	print "Sending Json: \n" + message
	s.send(message)
	data = s.recv(BUFFER_SIZE)
	print  "Receiving Json: \n" + data+"\n\n"
	s.close()
	return data

algorithms=["RAND_RP", "RAND_AUTO", "RAND_RDRAND"]
entropy=[0,1,2]
data_js='{"version":1,"algorithm":"RAND_RP","length":12, "entropy": 0}'


rand_js=json.loads(data_js)
for i in entropy:
    rand_js["entropy"]=i
    for j in algorithms:
        rand_js["algorithm"]=j
        sending(json.dumps(rand_js))
