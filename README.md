Welcome to Cryptoserer
 _______  _____  _     _ _______  ______ _______ __   _ _______ _______
 |       |     | |_____| |______ |_____/ |______ | \  | |       |______
 |_____  |_____| |     | |______ |    \_ |______ |  \_| |_____  |______

"Privacy is the power to selectively reveal oneself to the world." 
https://www.activism.net/cypherpunk/manifesto.html

Coherence

"Suitable connection or dependence, consistency" (in narrative or argument), also more literally "act or state of sticking or cleaving of one thing to another". 


Abstract

Coherence is and TCP server which provides an json interface to perfom cryptographic operations like encrypt, decrypt, digital signatures, key exchage, message authentication code, random numbers, hash functions.


Target

Be cryptoserver - (it's like openssl, tcp/json insted of bash)
Be an open source (software) alternative to HSM

 
Features

Hash functions: SHA3, SHA2, SHA1, WHIRLPOOL, Blake2b.
Stream ciphers: Sosemanuk, Salsa20/20.
Block ciphers: AES, RC6, MARS, Twofish, Serpent, CAST-256.
Block ciphers modes: CTR, GCM.
Message authentication codes: HMAC(SHA3, SHA2, SHA1, WHIRLPOOL),  CMAC(AES, RC6, MARS, Twofish, Serpent, CAST-256), VMAC(AES, RC6, MARS, Twofish, Serpent, CAST-256), Poly1305.
RSA: Key generation, digital signature, encryption and decryption.
DSA: Key generation, digital signature.
DH: Key generation, key exchange (rfc and custom parameters).
ECC: Key generation, ECIES, ECDSA, ECDH.


Quickstart

in bin folder, you have a coherence static version, it does not use shared libs, so you can run it.
when you run coherence, run sh testing.sh to test it.

