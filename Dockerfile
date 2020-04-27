FROM ubuntu:latest
RUN apt-get update -y
RUN apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" install -y autoconf automake gcc g++ make libtool git wget unzip xsltproc libssl-dev bzip2 valgrind doxygen graphviz python3 python3-pip cmake libcurl4-openssl-dev cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz git wget libargon2-dev pkg-config
RUN wget https://raw.githubusercontent.com/liesware/coherence/master/install.sh
RUN sh install.sh
RUN cp /core/coherence/core/bin/coherence /usr/bin/
# RUN cd /core/coherence/grpc && sh install.sh
# RUN rm -rf /core/*

# apt-get update
# apt-get install libssl-dev
# sh cp_libs.sh
# cp /core/coherence/core/bin/coherence /usr/bin/
