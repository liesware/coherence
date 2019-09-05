#!/bin/bash

cp lib/libuv/.libs/libuv.so.1.0.0 /lib/x86_64-linux-gnu/libuv.so.1
cp lib/cryptopp/libcryptopp.so.8.2.0 /lib/x86_64-linux-gnu/libcryptopp.so.8
cp lib/libntru/libntru.so /lib/x86_64-linux-gnu/
cp lib/liboqs/.libs/liboqs.so.0.0.0 /lib/x86_64-linux-gnu/liboqs.so.0
cp lib/argon2/libargon2.so.1 /lib/x86_64-linux-gnu/
ls -lha /lib/x86_64-linux-gnu/libuv.so.1
ls -lha /lib/x86_64-linux-gnu/libcryptopp.so.8
ls -lha /lib/x86_64-linux-gnu/libntru.so
ls -lha /lib/x86_64-linux-gnu/liboqs.so.0
ls -lha /lib/x86_64-linux-gnu/libargon2.so.1
