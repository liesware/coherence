import socket
import json
import os,binascii
import random

def sending(message):
	ip = '127.0.0.1'
	port = 6613
	BUFFER_SIZE = 65536
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((ip, port))
	s.send(message)
	data = s.recv(BUFFER_SIZE)
	s.close()
	return data

#int_len=random.randint(1,65536)
#test_bits=os.urandom(int_len)

#test_val='{"version":1,"algorithm":"QTESLA", "operation":"gen" ,"parameter":"qteslai"}'

data_js_n=sending(test_val)
print "Recived: \n" + data_js_n +"\n"
