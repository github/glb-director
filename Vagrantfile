# -*- mode: ruby -*-
# vi: set ft=ruby :

['vagrant-reload'].each do |plugin|
  unless Vagrant.has_plugin?(plugin)
    raise "Vagrant plugin #{plugin} is not installed!"
  end
end

Vagrant.configure("2") do |config|
  config.ssh.forward_agent = true

  config.vm.box = "debian/stretch64"

  config.vm.synced_folder "src/glb-wireshark-dissector/", "/home/vagrant/.config/wireshark/plugins/glb-wireshark-dissector", type: 'rsync'

  config.vm.provision :shell, inline: <<-SHELL
    echo 'deb http://ftp.debian.org/debian stretch-backports main' >/etc/apt/sources.list.d/backports.list
    apt-get update

    DEBIAN_FRONTEND=noninteractive apt-get -y dist-upgrade
    sudo apt install -y -t stretch-backports linux-image-amd64 linux-headers-amd64 iproute2

    DEBIAN_FRONTEND=noninteractive apt-get install -y tcpdump net-tools tshark build-essential libxtables-dev linux-headers-amd64 python-pip jq bird curl libsystemd-dev libbpf-dev

    groupadd wireshark || true
    usermod -a -G wireshark vagrant || true
    chgrp wireshark /usr/bin/dumpcap
    chmod 4750 /usr/bin/dumpcap
    pip install -r /vagrant/requirements.txt
  SHELL
  config.vm.provision :reload

  config.vm.define "router" do |v|
    v.vm.network "private_network", ip: "192.168.40.3", virtualbox__intnet: "glb_user_network"
    v.vm.network "private_network", ip: "192.168.50.2", virtualbox__intnet: "glb_datacenter_network", :mac=> "001122334455"
    v.vm.hostname = "router"

    v.vm.provision :shell, name: 'Enable forwarding and configure router', inline: <<-SHELL
      if ! grep -q '^net.ipv4.ip_forward' /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
        sysctl -w net.ipv4.ip_forward=1
      fi

      /vagrant/script/helpers/configure-vagrant-router.sh
    SHELL
  end

  config.vm.define "user" do |v|
    v.vm.network "private_network", ip: "192.168.40.2", virtualbox__intnet: "glb_user_network"
    v.vm.hostname = "user"

    v.vm.provision :shell, inline: <<-SHELL
      /vagrant/script/helpers/configure-vagrant-user.sh

      ip addr add 192.168.40.50/24 dev eth1 || true
      ip addr add 192.168.40.51/24 dev eth1 || true
      ip addr add 192.168.40.52/24 dev eth1 || true
      ip addr add 192.168.40.53/24 dev eth1 || true
      ip addr add 192.168.40.54/24 dev eth1 || true
      ip addr add 192.168.40.55/24 dev eth1 || true
    SHELL
  end

  def define_director(config, name, ipv4_addr, ipv6_addr, install_example_setup: false, example_setup_type: nil)
    config.vm.define name do |v|
      v.vm.hostname = name

      if install_example_setup
        v.vm.network "private_network", ip: ipv4_addr, virtualbox__intnet: "glb_datacenter_network", auto_config: false, nic_type: "82540EM"
      else
        v.vm.network "private_network", ip: ipv4_addr, virtualbox__intnet: "glb_datacenter_network"
      end

      v.vm.provider "virtualbox" do |vb|
        vb.cpus = 3
        vb.memory = "2048"

        # DPDK 17.08 and later require SSE4.2 - https://stackoverflow.com/a/48746498
        vb.customize ["setextradata", :id, "VBoxInternal/CPUM/SSE4.1", "1"]
        vb.customize ["setextradata", :id, "VBoxInternal/CPUM/SSE4.2", "1"]
      end

      v.vm.provision "shell", run: "always", inline: <<-SHELL
        mkdir -p /mnt/huge
        if ! grep -q 'hugetlbfs' /etc/fstab; then
          echo 'hugetlbfs /mnt/huge hugetlbfs mode=1770 0 0' >>/etc/fstab
          mount -t hugetlbfs nodev /mnt/huge
        fi
        if ! grep -q 'vm.nr_hugepages' /etc/sysctl.conf; then
          echo "vm.nr_hugepages=512" >> /etc/sysctl.conf
          sysctl -w vm.nr_hugepages=512
        fi

        if ! grep -q 'bpffs' /proc/mounts; then
          mount bpffs /sys/fs/bpf -t bpf
        fi
      SHELL

      # install DPDK et al.
      v.vm.provision "shell", run: "always", inline: <<-SHELL
        apt-get install -y apt-transport-https curl software-properties-common

        wget https://apt.llvm.org/llvm.sh
        chmod +x llvm.sh
        sudo ./llvm.sh 9

        curl -s https://packagecloud.io/install/repositories/github/unofficial-dpdk-stable/script.deb.sh | sudo bash
        apt-get install -y --force-yes linux-headers-amd64 # dpdk requires this for the current kernel, but won't block if not installed
        apt-get install -y python-pip dpdk-dev=17.11.1-6 dpdk=17.11.1-6 dpdk-rte-kni-dkms dpdk-igb-uio-dkms libjansson-dev
        apt-get install -y valgrind vim tcpdump git


        curl -O https://dl.google.com/go/go1.13.6.linux-amd64.tar.gz
        tar xvf go1.13.6.linux-amd64.tar.gz
        sudo chown -R root:root ./go
        sudo mv go /usr/local

        echo 'rte_kni' >/etc/modules-load.d/dpdk
        echo 'igb_uio' >>/etc/modules-load.d/dpdk
      SHELL

      v.vm.provision "shell", run: "always", inline: <<-SHELL
        sudo apt install -y dpdk-rte-kni-dkms dpdk-igb-uio-dkms
        modprobe rte_kni
        modprobe igb_uio
      SHELL

      if install_example_setup
        # example setup
        if example_setup_type == 'dpdk'
          v.vm.provision "shell", run: "always", inline: <<-SHELL
            ifdown eth1
            dpdk-devbind --bind=igb_uio eth1
            dpdk-devbind --status

            apt install /vagrant/tmp/build/glb-director-cli*.deb
            apt install /vagrant/tmp/build/glb-director_*.deb
            apt install /vagrant/tmp/build/glb-healthcheck_*.deb

            /vagrant/script/helpers/configure-vagrant-director.sh dpdk "#{ipv4_addr}"
          SHELL
        end

        if example_setup_type == 'xdp'
          v.vm.provision "shell", run: "always", inline: <<-SHELL
            DEBIAN_FRONTEND=noninteractive apt install -y /vagrant/tmp/build/glb-director-xdp_*.deb /vagrant/tmp/build/glb-director-cli_*.deb /vagrant/tmp/build/xdp-root-shim_*.deb
            DEBIAN_FRONTEND=noninteractive apt install -y /vagrant/tmp/build/glb-healthcheck_*.deb

            /vagrant/script/helpers/configure-vagrant-director.sh xdp "#{ipv4_addr}"
          SHELL
        end
      else
        # test setup
        v.vm.provision "shell", run: "always", inline: <<-SHELL
          ip addr add #{ipv6_addr} dev eth1 || true
        SHELL
      end
    end
  end

  def define_proxy(config, name, ipv4_addr, ipv6_addr)
    config.vm.define name do |v|
      v.vm.hostname = name

      v.vm.network "private_network", ip: ipv4_addr, virtualbox__intnet: "glb_datacenter_network"

      v.vm.provision "shell", inline: <<-SHELL
        DEBIAN_FRONTEND=noninteractive apt-get install -y nginx
        echo "hello world from #{name} via GLB" >/var/www/html/index.html
      SHELL

      v.vm.provision "shell", run: "always", inline: <<-SHELL
        modprobe fou
        modprobe sit
        ip link set up dev tunl0 || true
        ip link set up dev sit0 || true
        ip fou add port 19523 gue || true
        ip addr add 10.10.10.10/32 dev tunl0 || true
        ip addr add fd2c:394c:33a3:26bf::1/128 dev sit0 || true

        ip addr add #{ipv6_addr} dev eth1 || true

        ip route add 192.168.40.0/24 via 192.168.50.2 dev eth1 || true
        
        cp /vagrant/script/helpers/test-snoop.service /etc/systemd/system/test-snoop.service
        systemctl daemon-reload
        systemctl enable test-snoop.service
        systemctl restart test-snoop.service
      SHELL
    end
  end

  define_director config, "director-test", "192.168.50.5",  "fd33:75c6:d3f2:7e9f::5/64"
  define_director config, "director1",     "192.168.50.6",  "fd33:75c6:d3f2:7e9f::6/64", install_example_setup: true, example_setup_type: 'dpdk'
  define_director config, "director2",     "192.168.50.7",  "fd33:75c6:d3f2:7e9f::7/64", install_example_setup: true, example_setup_type: 'xdp'
  define_proxy    config,    "proxy1",     "192.168.50.10", "fd33:75c6:d3f2:7e9f::10/64"
  define_proxy    config,    "proxy2",     "192.168.50.11", "fd33:75c6:d3f2:7e9f::11/64"
end
