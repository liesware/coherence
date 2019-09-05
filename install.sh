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
mkdir cryptopp
cd cryptopp
wget https://www.cryptopp.com/cryptopp820.zip
unzip cryptopp820.zip
make libcryptopp.a libcryptopp.so cryptest.exe

cd ..
git clone https://github.com/tbuktu/libntru.git
cd libntru
make
make static-lib

cd ..
git clone https://github.com/Tencent/rapidjson.git

git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
git checkout master
autoreconf -i
 ./configure
make clean
make

cd ..
git clone https://github.com/oktal/pistache.git
cd pistache
git submodule update --init
mkdir build prefix
cd build
cmake -G "Unix Makefiles" \
        -DCMAKE_BUILD_TYPE=Release \
        -DPISTACHE_BUILD_EXAMPLES=false \
        -DPISTACHE_BUILD_TESTS=false \
        -DPISTACHE_BUILD_DOCS=false \
        -DPISTACHE_USE_SSL=false \
        -DCMAKE_INSTALL_PREFIX=$PWD/../prefix \
        ../
make -j
make install

cd ../../../
mkdir bin
make
