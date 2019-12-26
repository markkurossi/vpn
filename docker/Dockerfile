FROM ubuntu:18.04

RUN apt-get update
RUN apt-get install wget -y
RUN wget https://dl.google.com/go/go1.13.5.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.13.5.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"
RUN apt-get install dnsutils -y
RUN apt-get install gcc -y
RUN apt-get install module-init-tools -y
