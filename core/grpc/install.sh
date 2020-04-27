#!/bin/bash

git clone --recurse-submodules -b v1.28.1 https://github.com/grpc/grpc
cd grpc
mkdir -p cmake/build
cd cmake/build
cmake ../..
make
make install
cd ../../../
make
cd ..
sh cp_libs.sh
