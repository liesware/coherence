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
DEBIAN_FRONTEND="noninteractive" apt-get install -y autoconf automake gcc g++ make libtool git wget unzip xsltproc libssl-dev bzip2 valgrind doxygen graphviz python3 python3-pip cmake libcurl4-openssl-dev cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz git wget libargon2-dev pkg-config

git clone -b development https://github.com/liesware/coherence
cd coherence/core/lib/

git clone https://github.com/P-H-C/phc-winner-argon2
mv phc-winner-argon2/ argon2
cd argon2
make

cd ..
mkdir cryptopp
cd cryptopp
wget https://www.cryptopp.com/cryptopp850.zip
unzip cryptopp850.zip
make libcryptopp.a libcryptopp.so

cd ..
git clone https://github.com/tbuktu/libntru.git
cd libntru
make
make static-lib

cd ..
git clone https://github.com/Tencent/rapidjson.git

wget https://github.com/open-quantum-safe/liboqs/archive/refs/tags/0.7.0.zip
unzip 0.*.zip
mv liboqs-* liboqs
rm -f 0.*.0.zip
cd liboqs
mkdir build && cd build
cmake -DBUILD_SHARED_LIBS=ON -DOQS_USE_OPENSSL=ON -GNinja ..
ninja

cd ../../
git clone https://github.com/open-quantum-safe/liboqs-cpp

git clone https://github.com/liesware/pistache.git
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

cd grpc
git clone --recurse-submodules -b v1.38.0 https://github.com/grpc/grpc
cd grpc
mkdir -p cmake/build
cd cmake/build
cmake -DgRPC_BUILD_TESTS=OFF ../..
make -j
make install
cd ../../third_party/abseil-cpp
mkdir -p cmake/build
cd cmake/build
cmake -DCMAKE_POSITION_INDEPENDENT_CODE=TRUE ../..
make -j
make install
cd ../../../../../
make
cd ..

cp lib/pistache/prefix/lib/libpistache*so.0* /lib/x86_64-linux-gnu/libpistache.so.0
cp lib/cryptopp/libcryptopp.so.8.*.0 /lib/x86_64-linux-gnu/libcryptopp.so.8
cp lib/libntru/libntru.so /lib/x86_64-linux-gnu/
cp lib/liboqs/build/lib/liboqs.so.0.*.0 /lib/x86_64-linux-gnu/liboqs.so.0
cp lib/argon2/libargon2.so.1 /lib/x86_64-linux-gnu/
ls -lha /lib/x86_64-linux-gnu/libpistache.so.0
ls -lha /lib/x86_64-linux-gnu/libcryptopp.so.8
ls -lha /lib/x86_64-linux-gnu/libntru.so
ls -lha /lib/x86_64-linux-gnu/liboqs.so.0
ls -lha /lib/x86_64-linux-gnu/libargon2.so.1
ls -lha /lib/x86_64-linux-gnu/libpistache.so.0
cp bin/coherence grpc/coherence_grpc /usr/bin/
ls -lha /usr/bin/coherence*
