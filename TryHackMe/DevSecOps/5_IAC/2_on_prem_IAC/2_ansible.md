# Ansible: Introduction and Terminology

### What is Ansible?

Ansible is an open-source automation tool used for configuration management, application deployment, and task automation. It performs version control on the steps executed, meaning it only updates steps that require updates, similar to Docker, instead of reprovisioning everything from scratch.
Terminology

    Playbook: A YAML file containing a series of steps to be executed.
    
    Template: Base files with placeholders for Ansible variables that are injected at runtime to create deployable files.
    
    Role: A collection of templates and instructions that can be assigned to hosts for execution.
    
    Variable: Stores values used in deployment scripts. Ansible can use variable files to manage different values for the same variables based on runtime decisions.
    

### Ansible Example

Ansible relies on a specific folder and file structure. Here's a typical structure:

```

.
├── playbook.yml
├── roles
│   ├── common
│   │   ├── defaults
│   │   │   └── main.yml
│   │   ├── tasks
│   │   │   ├── apt.yml
│   │   │   ├── main.yml
│   │   │   ├── task1.yml
│   │   │   ├── task2.yml
│   │   │   └── yum.yml
│   │   ├── templates
│   │   │   ├── template1
│   │   │   └── template2
│   │   └── vars
│   │       ├── Debian.yml
│   │       └── RedHat.yml
│   ├── role2
│   ├── role3
│   └── role4
└── variables
    └── var.yml
```

### Playbook

The playbook.yml file defines what roles and variables will be applied:

```yaml

---
- name: Configure the server
  hosts: all
  become: yes
  roles:
    - common
    - role3
  vars_files:
    - variables/var.yml
```

### Role Definition

Roles contain multiple components. Here’s the main.yml file in the common role:

```yaml

---
- name: include OS specific variables
  include_vars: "{{ item }}"
  with_first_found:
    - "{{ ansible_distribution }}.yml"
    - "{{ ansible_os_family }}.yml"

- name: set root password
  user:
    name: root
    password: "{{ root_password }}"
  when: root_password is defined

- include: apt.yml
  when: ansible_os_family == "Debian"

- include: yum.yml
  when: ansible_os_family == "RedHat"

- include: task1.yml
- include: task2.yml
```
```
    Variable Inclusion: Loads OS-specific variables.

    Root Password: Sets the root password if defined.

    OS-Specific Tasks: Executes package management tasks based on the OS.

    General Tasks: Executes additional tasks.
```

### Combining Vagrant and Ansible

Combining Vagrant and Ansible can enhance your IaC pipeline. Vagrant can handle the deployment of hosts, while Ansible can manage host-specific configurations. This allows for efficient incremental updates without full reprovisioning.
Example Vagrantfile with Ansible

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

    # Ansible provisioning
    config.vm.provision "ansible_local" do |ansible|
      ansible.playbook = "provision/playbook.yml"
      ansible.become = true
    end
  end
end
```

This setup tells Vagrant to provision a VM and then use Ansible to configure it.
Comparison of Vagrant and Ansible
| Feature/Aspect              | Vagrant                            | Ansible                                 |
|-----------------------------|------------------------------------|-----------------------------------------|
| Configuration Language      | Ruby (for Vagrantfiles)            | YAML (for Playbooks)                    |
| Integration with Other Tools| Often used with Chef, Puppet, etc. | Standalone or integrated with CI/CD     |
| Complexity                  | Straightforward for dev environments | Higher for large infrastructures       |
| Scalability                 | Suited for smaller environments    | Highly scalable for complex applications|
| Execution Model             | Procedural with sequential steps   | Declarative describing desired state    |

Next Steps: Building Your IaC Pipeline
