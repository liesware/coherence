#!/bin/bash

# docker run -it -v  "$(pwd)"/release2/:/release --name coherence_rd ubuntu:latest /bin/bash
#   apt-get update
#   apt-get install -y libssl-dev
#   cp libs & bin
# docker rmi liesware/coherence:rd
# docker commit coherence_rd liesware/coherence:rd
# docker login
# docker push liesware/coherence:rd

apt-get update
DEBIAN_FRONTEND="noninteractive" apt-get install -y autoconf automake gcc g++ make libtool git wget unzip xsltproc libssl-dev bzip2 valgrind doxygen graphviz python3 python3-pip cmake libcurl4-openssl-dev cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz git wget libargon2-dev pkg-config meson astyle python3-yaml

git clone -b master https://github.com/liesware/coherence
cd coherence/core/lib/

git clone https://github.com/P-H-C/phc-winner-argon2
mv phc-winner-argon2/ argon2
cd argon2
make

cd ..
mkdir cryptopp
cd cryptopp
wget https://www.cryptopp.com/cryptopp890.zip
unzip cryptopp890.zip
make libcryptopp.a libcryptopp.so

cd ..
git clone https://github.com/Tencent/rapidjson.git

# git clone -b main https://github.com/open-quantum-safe/liboqs.git
wget https://github.com/open-quantum-safe/liboqs/archive/refs/tags/0.9.1.zip
unzip 0.9.1.zip
mv liboqs-0.9.1 liboqs
mv 0.9.1.zip liboqs
cd liboqs
mkdir build && cd build
cmake -DBUILD_SHARED_LIBS=ON -GNinja ..
ninja

cd ../../
git clone https://github.com/open-quantum-safe/liboqs-cpp
sed -i '40 i std::string LIBOQS_CPP_VERSION="0.9.1";' liboqs-cpp/include/common.h

git clone https://github.com/pistacheio/pistache.git
cd pistache
meson setup build
meson compile -C build

cd ../../
mkdir bin
make

cp lib/pistache/build/src/libpistache.so.0.2.7 /lib/x86_64-linux-gnu/libpistache.so.0
cp lib/cryptopp/libcryptopp.so.8.9.0 /lib/x86_64-linux-gnu/libcryptopp.so.8
cp lib/liboqs/build/lib/liboqs.so.0.9.1 /lib/x86_64-linux-gnu/liboqs.so.4
ls -lha /lib/x86_64-linux-gnu/libpistache.so.0
ls -lha /lib/x86_64-linux-gnu/libcryptopp.so.8
ls -lha /lib/x86_64-linux-gnu/liboqs.so.4
ls -lha /lib/x86_64-linux-gnu/libargon2.so.1
ls -lha /lib/x86_64-linux-gnu/libpistache.so.0
ldd bin/coherence 