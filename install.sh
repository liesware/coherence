#!/bin/bash

# apt-get update
# apt-get install -y autoconf automake gcc g++ make libtool git wget unzip xsltproc libssl-dev bzip2 valgrind doxygen graphviz python3 python3-pip cmake libcurl4-openssl-dev cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz git wget libargon2-dev

git clone https://github.com/liesware/coherence
cd coherence/core/lib/

git clone https://github.com/P-H-C/phc-winner-argon2
mv phc-winner-argon2/ argon2
cd argon2
make

cd ..
mkdir cryptopp
cd cryptopp
wget https://www.cryptopp.com/cryptopp820.zip
unzip cryptopp820.zip
make libcryptopp.a libcryptopp.so

cd ..
git clone https://github.com/tbuktu/libntru.git
cd libntru
make
make static-lib

cd ..
git clone https://github.com/Tencent/rapidjson.git

git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -DBUILD_SHARED_LIBS=ON -DOQS_USE_OPENSSL=ON -GNinja ..
ninja

cd ../../
git clone https://github.com/open-quantum-safe/liboqs-cpp

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
sh cp_libs.sh
mkdir bin
make
