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
	s.send(message)
	print "Sending Json: \n" + message
	data = s.recv(BUFFER_SIZE)
	print  "Receiving Json: \n" + data+"\n\n"
	s.close()
	return data


data_js='{"version":1,"algorithm":"MONIT","operation":"status"}'
sending(data_js)
