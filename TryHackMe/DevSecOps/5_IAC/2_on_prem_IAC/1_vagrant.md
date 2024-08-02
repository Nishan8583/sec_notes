# Vagrant: Introduction and Terminology
## What is Vagrant?

Vagrant is a tool for building and maintaining portable virtual software development environments. It can create and manage virtualized environments with ease, making it a valuable tool in the Infrastructure as Code (IaC) pipeline.
Terminology

    Provider: The virtualization technology used by Vagrant to provision the infrastructure. Examples include Docker, VirtualBox, VMware, and AWS.
    Provision: The action performed by Vagrant, such as adding files or running scripts to configure the host.
    Configure: Making configuration changes using Vagrant, like adding a network interface or changing a hostname.
    Variable: A storage entity for values used in the Vagrant deployment script.
    Box: The image that Vagrant will provision.
    Vagrantfile: The provisioning file executed by Vagrant.

## Vagrant Example

Here's an example of a Vagrant provisioning script and a simple project structure:
```
.
├── provision
│   ├── files.zip
│   └── script.sh
└── Vagrantfile
```
### Vagrantfile Script

```ruby

Vagrant.configure("2") do |cfg|
  cfg.vm.define "server" do |config|
    config.vm.box = "ubuntu/bionic64"
    config.vm.hostname = "testserver"
    config.vm.provider :virtualbox do |v, override|
       v.gui = false 
       v.cpus = 1
       v.memory = 4096
    end

    config.vm.network :private_network,
        :ip => 172.16.2.101
    config.vm.network :private_network,
        :ip => 10.10.10.101
  end

  cfg.vm.define "server2" do |config|
    config.vm.box = "ubuntu/bionic64"
    config.vm.hostname = "testserver2"
    config.vm.provider :virtualbox do |v, override|
       v.gui = false 
       v.cpus = 2
       v.memory = 4096
    end

    #Upload resources
    config.vm.provision "file", source: "provision/files.zip", destination: "/tmp/files.zip"

    #Run script
    config.vm.provision "shell", path: "provision/script.sh"
  end
end
```

Explanation

    Servers: Two servers are defined.
    Base Image: Both servers use the Ubuntu Bionic x64 image from a public repo.
    Configuration:
        Hostnames are set.
        CPUs and RAM are allocated.
        Network interfaces with static IPs are configured for the first server.
        The second server has a file uploaded and a script executed.

Commands

    To provision all servers: vagrant up
    To provision a specific server: vagrant up server


### Examples
- [AD](https://github.com/MWR-CyberSec/tabletop-lab-creation)
