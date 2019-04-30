FROM centos:7
RUN yum install -y glibc-static libstdc++-static autoconf automake gcc gcc-c++ make libtool git wget unzip
RUN wget https://raw.githubusercontent.com/liesware/coherence/master/install.sh
RUN sh install.sh
RUN cp /coherence_git/coherence/coherence02/bin/coherence /usr/bin/
RUN cd /coherence_git/coherence/coherence02/grpc && sh install.sh
#RUN rm -rf /coherence_git/
