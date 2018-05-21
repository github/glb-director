# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "debian/stretch64"

  config.vm.synced_folder "src/wireshark-dissector/", "/home/vagrant/.wireshark", type: 'rsync'

  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y tcpdump net-tools tshark build-essential libxtables-dev linux-headers-$(uname -r) python-pip jq
    groupadd wireshark || true
    usermod -a -G wireshark vagrant || true
    chgrp wireshark /usr/bin/dumpcap
    chmod 4750 /usr/bin/dumpcap
    pip install -r /vagrant/requirements.txt
  SHELL

  # config.vm.define "tests" do |v|
  #   v.vm.network "private_network", ip: "192.168.50.2"

  #   v.vm.provision "shell", inline: <<-SHELL
  #     apt-get install -y scapy
  #   SHELL
  # end

  config.vm.define "director" do |v|
    v.vm.network "private_network", ip: "192.168.50.5"

    v.vm.provider "virtualbox" do |vb|
      vb.cpus = 3
      vb.memory = "5120"
      # vb.customize ["modifyvm", :id, "--nic2", "nat", "--nictype2", "82540EM"]

      # DPDK 17.08 and later require SSE4.2 - https://stackoverflow.com/a/48746498
      vb.customize ["setextradata", :id, "VBoxInternal/CPUM/SSE4.1", "1"]
      vb.customize ["setextradata", :id, "VBoxInternal/CPUM/SSE4.2", "1"]
    end

    v.vm.provision "shell", inline: <<-SHELL
      mkdir -p /mnt/huge
      if ! grep -q 'hugetlbfs' /etc/fstab; then
        echo 'hugetlbfs /mnt/huge hugetlbfs mode=1770 0 0' >>/etc/fstab
        mount -t hugetlbfs nodev /mnt/huge
      fi
      if ! grep -q 'vm.nr_hugepages' /etc/sysctl.conf; then
        echo "vm.nr_hugepages=512" >> /etc/sysctl.conf
        sysctl -w vm.nr_hugepages=512
      fi
    SHELL

    # install DPDK et al.
    v.vm.provision "shell", inline: <<-SHELL
      apt-get install -y apt-transport-https curl
      echo 'deb http://ftp.debian.org/debian jessie-backports main' >/etc/apt/sources.list.d/backports.list
      apt-get update
      curl -s https://packagecloud.io/install/repositories/github/unofficial-dpdk-stable/script.deb.sh | sudo bash
      apt-get install -y linux-headers-`(uname -r)` # dpdk requires this for the current kernel, but won't block if not installed
      apt-get install -y python-pip dpdk-dev dpdk-rte-kni-dkms dpdk-igb-uio-dkms libjansson-dev
      apt-get install -y valgrind vim tcpdump clang golang

      echo 'rte_kni' >/etc/modules-load.d/dpdk
      echo 'igb_uio' >>/etc/modules-load.d/dpdk
    SHELL

    v.vm.provision "shell", run: "always", inline: <<-SHELL
      modprobe rte_kni
      modprobe igb_uio
      #dpdk-devbind --bind=igb_uio eth1
      #dpdk-devbind --status
    SHELL

    v.vm.provision "shell", inline: <<-SHELL
      ip addr add fd33:75c6:d3f2:7e9f::5/64 dev eth1 || true
    SHELL
  end

  config.vm.define "proxy1" do |v|
    v.vm.network "private_network", ip: "192.168.50.10"

    v.vm.provision "shell", inline: <<-SHELL
      modprobe fou
      modprobe sit
      ip link set up dev tunl0 || true
      ip link set up dev sit0 || true
      ip fou add port 19523 gue || true
      ip addr add 10.10.10.10/32 dev tunl0 || true
      ip addr add fd2c:394c:33a3:26bf::1/128 dev sit0 || true

      ip addr add fd33:75c6:d3f2:7e9f::10/64 dev eth1 || true

      DEBIAN_FRONTEND=noninteractive apt-get install -y nginx
    SHELL
  end

  config.vm.define "proxy2" do |v|
    v.vm.network "private_network", ip: "192.168.50.11"

    v.vm.provision "shell", inline: <<-SHELL
      modprobe fou
      modprobe sit
      ip link set up dev tunl0 || true
      ip link set up dev sit0 || true
      ip fou add port 19523 gue || true
      ip addr add 10.10.10.10/32 dev tunl0 || true
      ip addr add fd2c:394c:33a3:26bf::1/128 dev sit0 || true

      ip addr add fd33:75c6:d3f2:7e9f::11/64 dev eth1 || true

      DEBIAN_FRONTEND=noninteractive apt-get install -y nginx
    SHELL
  end
end
