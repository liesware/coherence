#!/bin/bash

cp lib/libuv/.libs/libuv.so.1.0.0 /lib64/libuv.so.1
cp lib/cryptopp/libcryptopp.so.8.1.0 /lib64/libcryptopp.so.8
cp lib/libntru/libntru.so /lib64/
cp lib/liboqs/liboqs.so /lib64/
ls -lha /lib64/libuv.so.1
ls -lha /lib64/libcryptopp.so.8
ls -lha /lib64/libntru.so
ls -lha /lib64/liboqs.so
