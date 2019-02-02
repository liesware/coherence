#!/bin/bash

mkdir  coherence_git
cd coherence_git
git clone https://github.com/liesware/coherence
cd coherence/coherence02/lib/

git clone https://github.com/P-H-C/phc-winner-argon2
mv phc-winner-argon2/ argon2
cd argon2
make

cd ..
git clone https://github.com/weidai11/cryptopp
cd cryptopp
make libcryptopp.a libcryptopp.so cryptest.exe

cd ..
git clone https://github.com/tbuktu/libntru.git
cd libntru
make
make static-lib

cd ..
git clone https://github.com/libuv/libuv.git
cd libuv
sh autogen.sh
./configure
make

cd ..
git clone https://github.com/Tencent/rapidjson.git

git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
git checkout master
autoreconf -i
 ./configure --disable-sig-picnic --disable-kem-frodokem --disable-kem-sike --disable-kem-newhope --disable-kem-kyber --disable-sig-picnic
make clean
make

cd ../../
mkdir bin
make
