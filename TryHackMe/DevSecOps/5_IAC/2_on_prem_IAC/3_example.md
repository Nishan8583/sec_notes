# Example
- Assumming the files in directory  /home/ubuntu/iac/ directory.

### Vagrantfile Configuration:

##### DB Server:
            IP: 172.20.128.3
            Uses Docker with the mysql image.
            MySQL root password: mysecretpasswd
            Configuration:

```ruby

    config.vm.define "dbserver"  do |cfg|
      cfg.vm.network :private_network, ip: "172.20.128.3"
      cfg.vm.provider "docker" do |d|
        d.image = "mysql"
        d.env = { "MYSQL_ROOT_PASSWORD" => "mysecretpasswd" }
      end
    end
```
##### Web Server:

    IP: 172.20.128.2
    Uses Docker with the ansible2 image.
    SSH configuration with username and private key.
    Runs Ansible playbook:

```ruby

        config.vm.define "webserver"  do |cfg|
          cfg.vm.network :private_network, ip: "172.20.128.2"
          cfg.vm.synced_folder "./provision", "/tmp/provision"
          cfg.vm.provider "docker" do |d|
            d.image = "ansible2"
            d.has_ssh = true
            d.cmd = ["/usr/sbin/sshd", "-D"]
          end
          cfg.ssh.username = 'root'
          cfg.ssh.private_key_path = "/home/ubuntu/iac/keys/id_rsa"
          cfg.vm.provision "shell", inline: "ansible-playbook /tmp/provision/web-playbook.yml"
        end
```
### Complete Vagrantfile
```ruby
Vagrant.configure("2") do |config|
  # DB server will be the backend for our website
  config.vm.define "dbserver"  do |cfg|
    # Configure the local network for the server
    cfg.vm.network :private_network, type: "dhcp", docker_network__internal: true
    cfg.vm.network :private_network, ip: "172.20.128.3", netmask: "24"

    # Boot the Docker container and run Ansible
    cfg.vm.provider "docker" do |d|
      d.image = "mysql"
      d.env = {
        "MYSQL_ROOT_PASSWORD" => "mysecretpasswd"
      }
    end
  end


  # Webserver will be used to host our website
  config.vm.define "webserver"  do |cfg|
    # Configure the local network for the server
    cfg.vm.network :private_network, type: "dhcp", docker_network__internal: true
    cfg.vm.network :private_network, ip: "172.20.128.2", netmask: "24"

    # Link the shared folder with the hypervisor to allow data passthrough. Will remove later to harden
    cfg.vm.synced_folder "./provision", "/tmp/provision"
    cfg.vm.synced_folder "/home/ubuntu/", "/tmp/datacopy"

    # Boot the Docker container and run Ansible
    cfg.vm.provider "docker" do |d|
      d.image = "ansible2"

      #d.cmd = ["ansible-playbook", "/tmp/provision/web-playbook.yml"]
      d.has_ssh = true

      # Command will keep the container active
      d.cmd = ["/usr/sbin/sshd", "-D"]
    end

    #We will connect using SSH so override the defaults here
    cfg.ssh.username = 'root'
    cfg.ssh.private_key_path = "/home/ubuntu/iac/keys/id_rsa"

    #Provision this machine using Ansible 
    cfg.vm.provision "shell", inline: "ansible-playbook /tmp/provision/web-playbook.yml"
  end

end

```
### Ansible Playbook (web-playbook.yml):

##### Runs the webapp role:

```yaml

    - hosts: localhost
      connection: all
      roles:
        - webapp
```
##### Webapp Role Tasks:

    DB Setup (db-setup.yml):
        Creates temp folder, delays for SQL server, copies and executes SQL scripts, and cleans up:

```yaml

    - name: Create temp folder for SQL scripts
      ansible.builtin.file:
        path: /tmp/sql
        state: directory

    - name: Time delay to allow SQL server to boot
      shell: sleep 10

    - name: Copy DB creation script with injected variables
      template:
        src: templates/createdb.sql
        dest: /tmp/sql/createdb.sql

    - name: Copy DB SP script with injected variables
      template:
        src: templates/createsp.sql
        dest: /tmp/sql/createsp.sql

    - name: Create DB
      shell: mysql -u {{ db_user }} -p{{ db_password }} -h {{ db_host }} < /tmp/sql/createdb.sql

    - name: Create Stored Procedures
      shell: mysql -u {{ db_user }} -p{{ db_password }} -h {{ db_host }} < /tmp/sql/createsp.sql

    - name: Cleanup Scripts
      shell: rm -r /tmp/sql
```
##### Web Setup (app-setup.yml):

    Copies web application files and the Flask app script:

```yaml

        - name: Copy web application files
          shell: cp -r /vagrant/provision/roles/webapp/templates/app /

        - name: Copy Flask app script with injected variables
          template:
            src: templates/app.py
            dest: /app/app.py
```
##### Default Variables (~/iac/provision/roles/webapp/defaults/main.yml):

    Defines database and API settings:

```yaml

    db_name: BucketList
    db_user: root
    db_password: mysecretpasswd
    db_host: 172.20.128.3
    api_key: superapikey
```
##### SQL Creation Script (templates/createdb.sql):

    Template for creating the database:

```sql

    drop DATABASE IF EXISTS {{ db_name }};

    CREATE DATABASE {{ db_name }};
    USE {{ db_name }};

    drop TABLE IF EXISTS 'tbl_user';

    CREATE TABLE {{ db_name }}.tbl_user ( 
      'user_id' BIGINT AUTO_INCREMENT, 
      'user_name' VARCHAR(45) NULL, 
      'user_username' VARCHAR(45) NULL, 
      'user_password' VARCHAR(162) NULL, 
      PRIMARY KEY ('user_id'));
```
Running the Pipeline:

    Execute vagrant up from the iac directory to start the provisioning process.
