#!/bin/bash

# Generate valid CA
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj  "/C=LI/ST=Liesland/L=Lies/O=Test/OU=Test/CN=Root CA"

# Generate valid Server Key/Cert
openssl genrsa -out server.key 2048
openssl req  -new -key server.key -out server.csr -subj  "/C=LI/ST=Liesland/L=Lies/O=Test/OU=Server/CN=localhost"
openssl x509 -req  -days 365 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt

# Remove passphrase from the Server Key
openssl rsa  -in server.key -out server.key

# Generate valid Client Key/Cert
openssl genrsa -out client.key 2048
openssl req  -new -key client.key -out client.csr -subj  "/C=LI/ST=Liesland/L=Lies/O=Test/OU=Client/CN=localhost"
openssl x509  -req -days 365 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out client.crt
