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

Coherence is a TCP server which provides an json interface to perfom cryptographic operations like encrypt, digital signatures, key exchage, message authentication code, random numbers, hash functions. For example it can be used for data base encryption.

 
## Features

* Hash functions: SHA3, SHA2, SHA1, WHIRLPOOL, Blake2b.
* Password-hashing function: Argon2
* Stream ciphers: Sosemanuk, Salsa20/20.
* Block ciphers: AES, RC6, MARS, Twofish, Serpent, CAST-256, Camellia.
* Block ciphers modes: CTR, GCM.
* Message authentication codes: HMAC(SHA3, SHA2, SHA1, WHIRLPOOL),  CMAC(AES, RC6, MARS, Twofish, Serpent, CAST-256, Camellia), VMAC(AES, RC6, MARS, Twofish, Serpent, CAST-256, Camellia), Poly1305.
* RSA: Key generation, digital signature, encryption.
* DSA: Key generation, digital signature.
* DH: Key generation, key exchange (rfc and custom parameters).
* ECC: Key generation, ECIES, ECDSA, ECDH.
* Post-Quantum Cryptography: NTRU.

## Quickstart (Linux)

Install glibc-static.
Inside bin folder there is a coherence version compile with -static, so you should not have problems to run it, because it does not depend on shared libs. 
```
git clone https://github.com/liesware/coherence.git
cd coherence/coherence02/bin/
chmod 550 coherence
./coherence 0.0.0.0 6613  
```
In other tab
```
cd coherence/coherence02/
sh testing.sh
```
The log file is print in standard output, so you can redirect the standard error and standard out messages to a log file.
```
./coherence 0.0.0.0 6613 > coherence.log 2>&1 &
```
## Docker image

```
git clone https://github.com/liesware/coherence.git

docker pull liesware/coherence:06

docker run -p 6613:6613 docker.io/liesware/coherence:06  /coherence/coherence 0.0.0.0 6613  > coherence.log 2>&1 &

cd coherence/coherence02/
sh testing.sh

```
https://hub.docker.com/r/liesware/coherence/

On windows you should not have problems , it is almost the same 

## Compile (*nix)
* Clone rapidjson 1.1.x (https://github.com/Tencent/rapidjson.git)
* Clone cryptopp 5.6.5 (http://github.com/weidai11/cryptopp/releases/tag/CRYPTOPP_5_6_5) and install (https://www.cryptopp.com/wiki/Compiling)
* Clone libuv 1.x (https://github.com/libuv/libuv.git) and install (see libuv Readme)
* Clone libargon2 (https://github.com/P-H-C/phc-winner-argon2) and install (see libargon2 Readme)
* Rename CRYPTOPP_5_6_5 to cryptopp, phc-winner-argon2 to argon2
* Move all libs inside lib folder
* make if you want a program with shared libs or make -f Makefile.static if you want a staic program.
* Makefiles are so simple (http://www.cs.colby.edu/maxwell/courses/tutorials/maketutor/), you can modify without problem

## Examples 
testing.sh exec argon2.py, dh.py, dsa.py, ecc.py, hash.js, mac.js, rand.js, rsa.py, stream.py.

The code is very simple and with basic programming knowledge you should be able to understand it.

## Wiki
Please see https://github.com/liesware/coherence/wiki

## Target

* Be cryptoserver (it's like openssl, tcp/json insted of bash)
* Be an open source kind of alternative to HSM
* Provide post quantum cryptography algorithms

## Version
This is the version 0.6, all the versions in github  are even, odd versions are to develop , even versions  are to fix bugs.

All the versions before 1.0 are called Essence.

## Contact

liesware 4t liesware d0t com , only concise and well-reasoned feedback are welcome. please be critic with yourself before writing.
