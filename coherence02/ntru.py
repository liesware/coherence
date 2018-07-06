import socket
import json
import os,binascii
import time

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

ntru_gen=json.loads('{ "version": 1 , "algorithm":"NTRU", "parameter": "EES1499EP1", "operation":"gen"}')
ntru_pam=["EES449EP1", "EES613EP1","EES761EP1","EES677EP1","EES887EP1","EES1087EP1","EES1087EP2","EES1171EP1","EES1499EP1"]
#ntru_pam=["EES613EP1"]

for i in ntru_pam:
	ntru_gen["parameter"]=i
	data_js_n=sending(json.dumps(ntru_gen))
	answ=json.loads(data_js_n)
	print "Recived gen NTRU: \n" + (json.dumps(answ)) +"\n"
	json_enc=json.loads('{ "version": 1 , "algorithm":"NTRU", "type":"string","pubkey": "" ,"operation":"enc", "plaintext":""}')
	json_enc["pubkey"]=answ["pubkey"]
	json_enc["parameter"]=answ["parameter"]
	json_enc["plaintext"]="It's only after we've lost everything that we're free to do anything."
	data_js_n=sending(json.dumps(json_enc))
	answ_1=json.loads(data_js_n)
	print "Recived enc NTRU: \n" + (json.dumps(answ_1)) +"\n\n\n"
	json_dec=json.loads('{ "version": 1 , "algorithm":"NTRU", "type":"string","privkey": "" ,"operation":"dec", "plaintext":""}')
	json_dec["privkey"]=answ["privkey"]
	json_dec["pubkey"]=answ["pubkey"]
	json_dec["parameter"]=answ["parameter"]
	json_dec["plaintext"]=answ_1["result"]
	data_js_n=sending(json.dumps(json_dec))
	answ_2=json.loads(data_js_n)
	print "Recived dec NTRU: \n" + (json.dumps(answ_2)) +"\n"
	json_pub=json.loads('{ "version": 1 , "algorithm":"NTRU", "parameter": "EES1499EP1", "operation":"gen_pub"}')
	json_pub["parameter"]=answ["parameter"]
	json_pub["privkey"]=answ["privkey"]
	data_js_n=sending(json.dumps(json_pub))
	answ_3=json.loads(data_js_n)
	print "Recived pub_gen NTRU: \n" + (json.dumps(answ_3)) +"\n\n\n"
	json_enc=json.loads('{ "version": 1 , "algorithm":"NTRU", "type":"string","pubkey": "" ,"operation":"enc", "plaintext":""}')
	json_enc["pubkey"]=answ_3["pubkey"]
	json_enc["parameter"]=answ["parameter"]
	json_enc["plaintext"]="It's only after we've lost everything that we're free to do anything."
	data_js_n=sending(json.dumps(json_enc))
	answ_4=json.loads(data_js_n)
	print "Recived enc NTRU: \n" + (json.dumps(answ_4)) +"\n\n\n"
	json_dec=json.loads('{ "version": 1 , "algorithm":"NTRU", "type":"string","privkey": "" ,"operation":"dec", "plaintext":""}')
	json_dec["privkey"]=answ["privkey"]
	json_dec["pubkey"]=answ_3["pubkey"]
	json_dec["parameter"]=answ["parameter"]
	json_dec["plaintext"]=answ_4["result"]
	data_js_n=sending(json.dumps(json_dec))
	answ_5=json.loads(data_js_n)
	print "Recived dec NTRU: \n" + (json.dumps(answ_5)) +"\n"
	
	
	
	
