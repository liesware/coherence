FROM debian:stretch
VOLUME ["/coherence_git"]
RUN apt.get update -y
RUN apt-get install -y autoconf automake gcc g++ make libtool git wget unzip libssl-dev
RUN wget https://raw.githubusercontent.com/liesware/coherence/experimental/install.sh
RUN sh install.sh
RUN cp /coherence_git/coherence/coherence02/bin/coherence /usr/bin/
