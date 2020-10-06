FROM ubuntu:latest
RUN apt-get update -y
RUN apt-get install -y wget
RUN wget https://raw.githubusercontent.com/liesware/coherence/dev/install.sh
RUN sh install.sh
