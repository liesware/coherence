#!/bin/bash

cd core/lib/

mkdir cryptopp
cd cryptopp
wget https://github.com/weidai11/cryptopp/releases/download/CRYPTOPP_8_9_0/cryptopp890.zip
unzip cryptopp890.zip
make libcryptopp.a libcryptopp.so

cd ..
git clone https://github.com/Tencent/rapidjson.git

wget https://github.com/open-quantum-safe/liboqs/archive/refs/tags/0.15.0.zip
unzip 0.15.0.zip
mv liboqs-0.15.0 liboqs
mv 0.15.0.zip liboqs
cd liboqs
mkdir build && cd build
cmake -DBUILD_SHARED_LIBS=ON -GNinja ..
ninja

cd ../../
git clone https://github.com/open-quantum-safe/liboqs-cpp
sed -i '' $'41i\\\nstd::string LIBOQS_CPP_VERSION="0.15.0";' liboqs-cpp/include/common.hpp

git clone https://github.com/pistacheio/pistache.git
cd pistache
meson setup build
meson compile -C build

cd ../../
mkdir bin
make

otool -L core/bin/coherence