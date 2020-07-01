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
  config.vm.synced_folder ".", "/vagrant", type: 'rsync'

  config.vm.provision :shell, inline: <<-SHELL
    ls -al /vagrant/
    echo 'deb http://ftp.debian.org/debian stretch-backports main' >/etc/apt/sources.list.d/backports.list

    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get -y dist-upgrade
    apt-get install -y -t stretch-backports linux-image-amd64 linux-headers-amd64 iproute2
    apt-get install -y tcpdump net-tools tshark build-essential libxtables-dev linux-headers-amd64 python-pip jq bird curl libsystemd-dev libbpf-dev

    groupadd wireshark || true
    usermod -a -G wireshark vagrant || true
    chgrp wireshark /usr/bin/dumpcap
    chmod 4750 /usr/bin/dumpcap
    pip install -r /vagrant/requirements.txt
    ifconfig 
  SHELL
  config.vm.provision :reload

  config.vm.define "router" do |v|
    v.vm.network :private_network, 
         :ip=> "192.168.40.3", 
	 :name => "glb_user_network",
	 :mode => "none",
	 :dhcp_enabled=> false,
	 :virtualbox__intnet=> "glb_user_network",
	 :libvirt__forward_mode => "none",
	 :libvirt__dhcp_enabled => false

    v.vm.network :private_network, 
         :ip=> "192.168.50.2", 
	 :mac=> "001122334455", 
	 :name => "glb_datacenter_network",
	 :mode => "none",
	 :dhcp_enabled=> false,
	 :virtualbox__intnet=> "glb_datacenter_network",
	 :libvirt__forward_mode => "none",
	 :libvirt__dhcp_enabled => false

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
    v.vm.network :private_network, 
         :ip=> "192.168.40.2", 
	 :name => "glb_user_network",
	 :mode => "none",
	 :dhcp_enabled=> false,
	 :virtualbox__intnet=> "glb_user_network",
	 :libvirt__forward_mode => "none",
	 :libvirt__dhcp_enabled => false
    v.vm.hostname = "user"

    v.vm.provision :shell, inline: <<-SHELL
      ifconfig 
      /vagrant/script/helpers/configure-vagrant-user.sh
      ip route del default via 192.168.121.1
      ip route add default via 192.168.40.3

      ip addr add 192.168.40.50/24 dev ens6 || true
      ip addr add 192.168.40.51/24 dev ens6 || true
      ip addr add 192.168.40.52/24 dev ens6 || true
      ip addr add 192.168.40.53/24 dev ens6 || true
      ip addr add 192.168.40.54/24 dev ens6 || true
      ip addr add 192.168.40.55/24 dev ens6 || true
    SHELL
  end

  def define_director(config, name, ipv4_addr, ipv6_addr, install_example_setup: "false", example_setup_type: nil)
    config.vm.define name do |v|
      v.vm.hostname = name

      if install_example_setup
	v.vm.network :private_network, 
	     :ip=> ipv4_addr, 
	     :auto_config=> false,
	     :nic_type => "82540EM",
	     :name => "glb_datacenter_network",
	     :mode => "none",
	     :dhcp_enabled=> false,
	     :virtualbox__intnet=> "glb_datacenter_network",
	     :libvirt__forward_mode => "none",
	     :libvirt__dhcp_enabled => false
      else
	v.vm.network :private_network, 
	     :ip=> ipv4_addr, 
	     :auto_config=> false,
	     :name => "glb_datacenter_network",
	     :mode => "none",
	     :dhcp_enabled=> false,
	     :virtualbox__intnet=> "glb_datacenter_network",
	     :libvirt__forward_mode => "none",
	     :libvirt__dhcp_enabled => false
      end

      v.vm.provider "libvirt" do |virt|
        virt.cpus = 3
        virt.memory = "2048"
	virt.nic_model_type = "e1000"
	virt.cpu_feature :name => 'sse4.1', :policy => 'require'
	virt.cpu_feature :name => 'sse4.2', :policy => 'require'
	virt.management_network_mode = "none"
      end

      v.vm.provider "virtualbox" do |vb|
        vb.cpus = 3
        vb.memory = "2048"

        # DPDK 17.08 and later require SSE4.2 - https://stackoverflow.com/a/48746498
        vb.customize ["setextradata", :id, "VBoxInternal/CPUM/SSE4.1", "1"]
        vb.customize ["setextradata", :id, "VBoxInternal/CPUM/SSE4.2", "1"]
      end

      v.vm.provision "shell", run: "always", inline: <<-SHELL
        ifconfig 
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
	export DEBIAN_FRONTEND=noninteractive
        apt-get install -y apt-transport-https curl software-properties-common

        wget --no-verbose https://apt.llvm.org/llvm.sh
        chmod +x llvm.sh
	[ ! -x ./llvm.sh ] && exit -1
	# use llvm v10 beceause v9 not evailable in https://apt.llvm.org/llvm.sh repository 
        sudo ./llvm.sh 10

        curl -s https://packagecloud.io/install/repositories/github/unofficial-dpdk-stable/script.deb.sh | sudo bash
        apt-get install -y --force-yes linux-headers-amd64 # dpdk requires this for the current kernel, but won't block if not installed
        apt-get install -y python-pip dpdk-dev=17.11.1-6 dpdk=17.11.1-6 dpdk-rte-kni-dkms dpdk-igb-uio-dkms libjansson-dev
        apt-get install -y valgrind vim tcpdump git

        curl -s -O https://dl.google.com/go/go1.13.6.linux-amd64.tar.gz
	[ ! -f go1.13.6.linux-amd64.tar.gz ] && exit -1
        tar xf go1.13.6.linux-amd64.tar.gz
	ls -al go go1.13.6.linux-amd64.tar.gz
        sudo chown -R root:root ./go
	sudo rm -rf /usr/local/go
        sudo mv go /usr/local

        echo 'rte_kni' >/etc/modules-load.d/dpdk
        echo 'igb_uio' >>/etc/modules-load.d/dpdk
      SHELL

      v.vm.provision "shell", run: "always", inline: <<-SHELL
	export DEBIAN_FRONTEND=noninteractive
        apt-get install -y --allow-unauthenticated dpdk-rte-kni-dkms dpdk-igb-uio-dkms
        modprobe rte_kni
        modprobe igb_uio
      SHELL

      if install_example_setup
        # example setup
        if example_setup_type == 'dpdk'
          v.vm.provision "shell", run: "always", inline: <<-SHELL
	    ip -j link show | python -m json.tool
            ifconfig ens6 down
            dpdk-devbind --bind=igb_uio ens6
            dpdk-devbind --status-dev "net"

            apt-get install -y --force-yes /vagrant/tmp/build/glb-director-cli_*.deb /vagrant/tmp/build/glb-director_*.deb
            apt-get install -y --force-yes /vagrant/tmp/build/glb-healthcheck_*.deb

            /vagrant/script/helpers/configure-vagrant-director.sh dpdk "#{ipv4_addr}"
          SHELL
        end

        if example_setup_type == 'xdp'
          v.vm.provision "shell", run: "always", inline: <<-SHELL
            apt-get install -y --force-yes /vagrant/tmp/build/glb-director-xdp_*.deb /vagrant/tmp/build/glb-director-cli_*.deb /vagrant/tmp/build/xdp-root-shim_*.deb
            apt-get install -y --force-yes /vagrant/tmp/build/glb-healthcheck_*.deb

            /vagrant/script/helpers/configure-vagrant-director.sh xdp "#{ipv4_addr}"
          SHELL
        end
      else
        # test setup
        v.vm.provision "shell", run: "always", inline: <<-SHELL
          ip addr add #{ipv6_addr} dev ens6 || true
	  ifconfig
        SHELL
      end
    end
  end

  def define_proxy(config, name, ipv4_addr, ipv6_addr)
    config.vm.define name do |v|
      v.vm.hostname = name

    v.vm.network :private_network, 
         :ip=> ipv4_addr, 
	 :name => "glb_datacenter_network",
	 :mode => "none",
	 :dhcp_enabled=> false,
	 :libvirt__forward_mode => "none",
	 :libvirt__dhcp_enabled => false

      v.vm.provision "shell", inline: <<-SHELL
        ifconfig 
        apt-get install -y nginx
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

        ip addr add #{ipv6_addr} dev ens6 || true

        ip route add 192.168.40.0/24 via 192.168.50.2 dev ens6 || true
        
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
