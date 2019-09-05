FROM debian:stretch
RUN apt-get update -y
RUN apt-get install -y autoconf automake gcc g++ make libtool git wget unzip xsltproc libssl-dev bzip2 valgrind doxygen graphviz python3 python3-pip && pip3 install pytest
RUN wget https://raw.githubusercontent.com/liesware/coherence/master/install.sh
RUN sh install.sh
RUN cp /coherence_git/coherence/coherence02/bin/coherence /usr/bin/
#RUN cd /coherence_git/coherence/coherence02/grpc && sh install.sh
RUN rm -rf /coherence_git/
