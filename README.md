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

**Make Javascript do Renders not Cryptography**

## This branch

In this branch  we are integrating postquatum algorithms and homomorphic encryption, pairing based cryptography , as well as new 
features. In master branch we include Qtesla as previous feature from this branch.
 
## Standard Features

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
* Post-Quantum Cryptography: NTRU.

## Experimental Features

* Qtesla

## Quickstart (Docker)

* wget https://raw.githubusercontent.com/liesware/coherence/experimental/Dockerfile
* docker build -t coherence:experimental .
* docker run -p 6613:6613 -it  coherence:experimental /usr/bin/coherence 0.0.0.0 6613

## Quickstart (Linux)

This version is based on Debian 9

For Debian 9 dependencies:
* apt-get install autoconf automake gcc g++ make libtool git wget unzip xsltproc libssl-dev

_This version is compiled with dynamic libs, so install.sh runs cp_libs.sh to copy the libs to /usr/lib/x86_64-linux-gnu/_

Now compile it:
* wget https://raw.githubusercontent.com/liesware/coherence/experimental/install.sh
* sh install.sh
* cd coherence_git/coherence/coherence02/bin ; ./coherence 0.0.0.0 6613
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

_You can use your favorite language, we are using python only for illustrative examples( your language needs to support TCP sockets
and json format)._

argon2.py  block.py  cmac.py  dh.py  dsa.py  ecc.py  hash.py  hmac.py  ntru.py  poly1305.py  qtesla.py  rand.py  rsa.py  stream.py  
vmac.py

The code is very simple and with basic programming knowledge you should be able to understand it. You only need to understand python 
tcp sockets and json format.

## Test
on ~/coherence02/

Terminal 1
* watch python ps_mem.py -p $(pidof coherence)

Terminal 2
* cd bin/ && ./coherence 0.0.0.0 6613

Terminal 3
* cd examples/ && sh all.sh

## Wiki
[RTFW](https://en.wikipedia.org/wiki/RTFM)

Please see https://github.com/liesware/coherence/wiki

## Target

* Be cryptoserver (server dedicated for cryptography)
* Improve security in L7 (Cryptography for webapps)

## Version

Current version Arche.

## Contact

liesware 4t liesware d0t com , only concise and well-reasoned feedback are welcome. please be critic with yourself before writing.

## Webpage

[Link](https://coherence.liesware.com/)
