#!/bin/bash

# Generate valid CA
openssl genrsa -out ca.key 2048
#openssl ecparam -name secp521r1 -genkey -out ca.key
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj  "/C=LI/ST=Liesland/L=Lies/O=Test/OU=Test/CN=Root CA"
openssl x509 -in ca.crt -text -noout

# Generate valid Server Key/Cert
openssl genrsa -out server.key 2048
#openssl ecparam -name secp256k1 -genkey -out server.key
openssl req  -new -key server.key -out server.csr -subj  "/C=LI/ST=Liesland/L=Lies/O=Test/OU=Server/CN=172.17.0.2"
openssl x509 -req  -days 365 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt
openssl x509 -in server.crt -text -noout

# Remove passphrase from the Server Key
#openssl rsa  -in server.key -out server.key

# Generate valid Client Key/Cert
openssl genrsa -out client.key 2048
#openssl ecparam -name prime256v1 -genkey -out client.key
openssl req  -new -key client.key -out client.csr -subj  "/C=LI/ST=Liesland/L=Lies/O=Test/OU=Client/CN=172.17.0.2"
openssl x509  -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 02 -out client.crt
openssl x509 -in client.crt -text -noout

python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. coherence.proto
