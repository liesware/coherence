#!/bin/bash

cp lib/pistache/prefix/lib/libpistache*so.0* /lib/x86_64-linux-gnu/libpistache.so.0
cp lib/cryptopp/libcryptopp.so.8.2.0 /lib/x86_64-linux-gnu/libcryptopp.so.8
cp lib/libntru/libntru.so /lib/x86_64-linux-gnu/
cp lib/liboqs/build/lib/liboqs.so.0.4.0 /lib/x86_64-linux-gnu/liboqs.so.0
cp lib/argon2/libargon2.so.1 /lib/x86_64-linux-gnu/
# cp lib/pistache/build/src/libpistache.so.0 /lib/x86_64-linux-gnu/
ls -lha /lib/x86_64-linux-gnu/libpistache.so.0
ls -lha /lib/x86_64-linux-gnu/libcryptopp.so.8
ls -lha /lib/x86_64-linux-gnu/libntru.so
ls -lha /lib/x86_64-linux-gnu/liboqs.so.0
ls -lha /lib/x86_64-linux-gnu/libargon2.so.1
ls -lha /lib/x86_64-linux-gnu/libpistache.so.0

cp bin/coherence /usr/bin/
cp grpc/coherence_grpc /usr/bin/
