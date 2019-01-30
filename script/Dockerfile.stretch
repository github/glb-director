FROM debian:stretch

RUN echo 'deb http://ftp.debian.org/debian stretch-backports main' >>/etc/apt/sources.list
RUN apt-get update && apt-get -y install curl

# DPDK 
RUN curl -s https://packagecloud.io/install/repositories/github/unofficial-dpdk-stable/script.deb.sh | bash
RUN apt-get update && apt-get install -y build-essential dpdk dpdk-dev wget pkg-config libjansson-dev

# iptables / DKMS
RUN apt-get update && apt-get install -y iptables-dev dkms debhelper libxtables-dev

# golang
RUN apt-get update && apt-get install -y golang golang-glide

# fpm for packaging
RUN apt-get update && apt-get install -y ruby ruby-dev rubygems build-essential
RUN gem install --no-ri --no-rdoc rake fpm

# patch DKMS for source package generation https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=832558
ADD helpers/dkms.diff /root/dkms.diff
RUN patch -d /usr/sbin </root/dkms.diff
