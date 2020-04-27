#!/bin/bash

git clone https://github.com/grpc/grpc
cd grpc
git submodule update --init
make
make install
cd third_party/protobuf
make
make install
cd ../../../
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
export LD_LIBRARY_PATH=/usr/local/lib
cd ..
sh cp_libs.sh
cd grpc/
make
sh install_py.sh
sh gen.sh
