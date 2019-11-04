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
The future of data breaches is not encouraging,  on 2017 less than 4% of data breaches the cryptography became the data stolen into data useless, with enterprise options as well as open source options to perform cryptography even so year in year out data breaches grow.

Coherence (ko.eˈɾen.s) performs and offloads cryptography operations with a focus on interoperability, flexibility and  simplicity. Coherence gives an interface for modern cryptographic algorithms which is inspired by Openssl, it is a REST API in order to be used by any language, in other words Coherence minimizes development time and code complexity. Some of the algorithms offered by Coherence are AES and AES candidates, Sosemanuk, SHA* family, HMAC, DH, RSA, DSA, ECC, NTRU.


**Closing the gap between web developers and cryptography**

 
## Features

* Hash functions: SHA3, SHA2, SHA1, WHIRLPOOL, Blake2b, SipHash.
* Password-hashing function: Argon2
* Stream ciphers: Sosemanuk, Salsa20/20.
* Block ciphers: AES, RC6, MARS, Twofish, Serpent, CAST-256, Camellia, SPECK, SIMECK.
* Block ciphers modes: CTR, GCM.
* Message authentication codes: HMAC(SHA3, SHA2, SHA1, WHIRLPOOL),  CMAC(AES, RC6, MARS, Twofish, Serpent, CAST-256, Camellia), VMAC(AES, RC6, MARS, Twofish, Serpent, CAST-256, Camellia), Poly1305.
* RSA: Key generation, digital signature, encryption.
* DSA: Key generation, digital signature.
* DH: Key generation, key exchange (rfc and custom parameters).
* ECC: Key generation, ECIES, ECDSA, ECDH, Curve25519, ECNR.
* Post-Quantum Cryptography sign: Qtesla, Dilithium, MQDSS, SPHINCS+.
* Post-Quantum Cryptography kem: NTRU, Kyber, Newhope, Saber, SIDH, Sike. 

**Be careful Post-Quantum Cryptography is not an standard yet and is experimental.**

## Quickstart (Docker image)

* docker pull liesware/coherence:latest
* docker run -p 6613:6613 -it liesware/coherence:latest /usr/bin/coherence

## Quickstar (Dockerfile)

* wget https://raw.githubusercontent.com/liesware/coherence/master/Dockerfile
* docker build -t coherence:master .
* docker run -p 6613:6613 -it  coherence:master /usr/bin/coherence

## Quickstart (Linux)

For Debian 9 dependencies:
* apt-get install autoconf automake gcc g++ make libtool git wget unzip xsltproc libssl-dev bzip2 valgrind doxygen graphviz python3 python3-pip cmake libcurl4-openssl-dev  && pip3 install pytest

Now compile it:
* wget https://raw.githubusercontent.com/liesware/coherence/master/install.sh
* sh install.sh
* cd coherence_git/coherence/coherence02/bin ; ./coherence 0.0.0.0 6613
* Run this code

```python 
#!/usr/bin/env python

import requests
import json
import os,binascii

def sending(message):
	url = 'http://127.0.0.1:6613/'
	response=requests.post(url, data=message)
	print response.content

data_js='{"version":1,"algorithm":"SHA3_512","type":"string","plaintext":"Hello world!"}'
sending(data_js)
```
We are getting SHA3-512 for "Hello world!" string.

## Examples 

_You can use your favorite language, we are using python only for illustrative examples_

argon2.py  block.py  cmac.py  dh.py  dsa.py  ecc.py  hash.py  hmac.py  ntru.py  poly1305.py  qtesla.py  rand.py  rsa.py  stream.py  
vmac.py

The code is very simple and with basic programming knowledge you should be able to understand it. You only need to understand python and REST API

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
Current version Essence.

## Branches

* Master: Stable, standard and experimental algorithms. 

## Bugs

Through Github

## Contact
We will be so happy to listent to you, only concise and well-reasoned feedback are welcome. please be critic with yourself before 
writing. 

_coherence 4t liesware d0t com_ 

## Webpage

[Link](https://coherence.liesware.com/)
