# Welcome to (Cryptoserver)
<pre>
 _______  _____  _     _ _______  ______ _______ __   _ _______ _______
 |       |     | |_____| |______ |_____/ |______ | \  | |       |______
 |_____  |_____| |     | |______ |    \_ |______ |  \_| |_____  |______

 </pre>

"Privacy is the power to selectively reveal oneself to the world". Eric Hughes
- https://www.activism.net/cypherpunk/manifesto.html
- http://www.coderfreedom.org/
- https://pastebin.com/t6B6fhcv

# Coherence

"Suitable connection or dependence, consistency" (in narrative or argument), also more literally "act or state of sticking or cleaving of one thing to another". 


## Abstract
Cohenrence is cryptographic server, it provides a TCP server whith an json interface to perfom cryptographic operations. It helps you to create your own cryptographic protocols for modern web apps to protect data, for exmaple: data base encryption, digital signatures, file encryption.


 
## Features

* Hash functions: SHA3, SHA2, SHA1, WHIRLPOOL, Blake2b.
* Password-hashing function: Argon2
* Stream ciphers: Sosemanuk, Salsa20/20.
* Block ciphers: AES, RC6, MARS, Twofish, Serpent, CAST-256, Camellia, SPECK, SIMECK.
* Block ciphers modes: CTR, GCM.
* Message authentication codes: HMAC(SHA3, SHA2, SHA1, WHIRLPOOL),  CMAC(AES, RC6, MARS, Twofish, Serpent, CAST-256, Camellia), VMAC(AES, RC6, MARS, Twofish, Serpent, CAST-256, Camellia), Poly1305.
* RSA: Key generation, digital signature, encryption.
* DSA: Key generation, digital signature.
* DH: Key generation, key exchange (rfc and custom parameters).
* ECC: Key generation, ECIES, ECDSA, ECDH.
* Post-Quantum Cryptography: NTRU, Qtesla.

Be careful qtesla is not an standard yet and is experimental

## Quickstart (Linux)

For Centos 7 dependencies:
* yum install glibc-static libstdc++-static autoconf automake gcc gcc-c++ make libtool git wget

For Debian 9 dependencies:
* apt-get install autoconf automake gcc g++ make libtool git wget

Now compile it:
* wget https://raw.githubusercontent.com/liesware/coherence/master/install.sh
* sh install.sh
* Run this code

```python 
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
	data = s.recv(BUFFER_SIZE)
        print data
	s.close()
	return data

data_js='{"version":1,"algorithm":"SHA3_512","type":"string","plaintext":"Hello world!"}'
sending(data_js)
```
We are getting SHA3-512 for "Hello world!" string.

## Examples 
argon2.py  block.py  cmac.py  dh.py  dsa.py  ecc.py  hash.py  hmac.py  ntru.py  poly1305.py  qtesla.py  rand.py  rsa.py  stream.py  
vmac.py

The code is very simple and with basic programming knowledge you should be able to understand it.

## Test
on ~/coherence02/

Terminal 1
* watch python ps_mem.py -p $(pidof coherence)

Terminal 2
* cd bin/ && ./coherence 0.0.0.0 6613

Terminal 3
* cd examples/ && sh all.sh

## Wiki
Please see https://github.com/liesware/coherence/wiki

## Target

* Be cryptoserver (server dedicated for cryptography)
* Improve security in L7 (Cryptography for webapps)

## Version
This is the version 0.7, all the versions in github  are even, odd versions are to develop , even versions  are to fix bugs.

All the versions before 1.0 are called Essence.

## Contact

liesware 4t liesware d0t com , only concise and well-reasoned feedback are welcome. please be critic with yourself before writing.

## Webpage

[Link](https://coherence.liesware.com/)
