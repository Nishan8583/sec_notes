### Tool
1. [Grype](https://github.com/anchore/grype)
```
Scan a Docker image for vulnerabilities.
grype imagename --scope all-layers

Scan an exported container filesystem (i.e. from docker image save).
grype /path/to/image.tar
```
2. [Dive](https://github.com/wagoodman/dive)
```dive <your-image-tag>```



### 1. Access
Docker Daemon and Security:

    Docker daemon manages containers and images.
    Often used remotely in CI/CD pipelines.
    Attackers interacting with the Docker daemon can launch malicious containers or access sensitive applications.

Exposure and Security Measures:

    Docker daemon is not network-exposed by default; manual configuration is required.
    Commonly exposed in cloud environments for CI/CD.
    Secure communication and authentication methods are essential to prevent unauthorized access.

SSH Authentication:

    Developers use SSH to interact with remote Docker instances via contexts (profiles).
    Contexts allow switching between configurations for different devices (development, production).
    Example provided for creating and using Docker contexts.
    Emphasizes strong password hygiene for SSH security.

TLS Encryption:

    Docker daemon can use HTTP/S with TLS for secure communication.
    TLS encrypts data between devices and ensures only authorized devices can interact.
    Requires managing TLS certificates (not covered in detail).
    Example provided for configuring Docker in TLS mode.

Security Considerations:

    Both SSH and TLS methods have potential vulnerabilities (e.g., weak SSH passwords, valid certificates in wrong hands).
    Strong password practices and careful management of certificates are crucial.

### 2. Implementing Control Groups
Control Groups (cgroups):

    Feature of the Linux kernel for restricting and prioritizing system resources for processes.
    Improves system stability and allows better tracking of resource usage.

Docker and cgroups:

    Used to achieve isolation and stability in Docker containers.
    Prevents faulty or malicious containers from exhausting system resources.
    Acts as a second line of defense to prevent a container from bringing down the whole system.

Enabling cgroups in Docker:

    Not enabled by default; must be specified per container.
    Arguments for resource limits:
        CPU: --cpus (e.g., docker run -it --cpus="1" mycontainer)
        Memory: --memory (e.g., docker run -it --memory="20m" mycontainer)
    Can update resource limits using docker update (e.g., docker update --memory="40m" mycontainer).

Inspecting Container Resource Limits:

    Use docker inspect containername to view resource limits.
    A resource limit set to 0 indicates no limits are set.

Namespaces in Docker:

    Creates isolated environments for processes.
    Provides security by ensuring actions in one namespace do not affect other processes.

### 3. Seccomp and Armor
    Seccomp:
        A Linux security feature that restricts system calls an application can make.
        Works like a security guard, enforcing rules on permitted actions.
        Example profile allows file operations but denies execution (execve).

    Creating and Applying Seccomp Profiles:
        Profiles can be created in a text editor.
        Apply profiles using the --security-opt seccomp flag in Docker (e.g., docker run --rm -it --security-opt seccomp=/path/to/profile.json mycontainer).

    AppArmor:
        A Mandatory Access Control (MAC) system that limits actions at the OS level.
        Profiles determine what resources an application can access and what actions it can take.
        Example profile restricts an Apache web server’s file access and network bindings.

    Creating and Applying AppArmor Profiles:
        Ensure AppArmor is installed (sudo aa-status).
        Create a profile, load it using apparmor_parser, and apply it using the --security-opt apparmor flag in Docker (e.g., docker run --rm -it --security-opt apparmor=/path/to/profile.json mycontainer).

    Difference Between Seccomp and AppArmor:
        AppArmor controls resource access and actions at the OS level.
        Seccomp restricts system calls within the program.
        Both can be combined for enhanced security in Docker containers.

### 4. Review Dcker Images
Importance of Reviewing Docker Images:

    Running unknown Docker images is risky, similar to running unknown code on a device.
    Malicious Docker images, like cryptomining images discovered in 2020, have caused significant issues.

Inspecting Docker Images on Docker Hub:

    Docker Hub displays image layers, showing the steps executed during the build process.
    Images often include Dockerfiles, allowing for code review and auditing.

Analyzing Dockerfiles:

    Reviewing Dockerfiles helps understand actions taken by the container and identify potential vulnerabilities or malicious behavior.

Tools for Docker Image Analysis:

    Tools like [Dive](https://github.com/wagoodman/dive) enable reverse engineering of Docker images, inspecting changes and executions at each layer during the build process.

### 5. Compliance and Benchmark
Compliance:

    Definition: Compliance is adhering to regulations and standards to ensure security.
    Examples:
        NIST SP 800-190: Provides guidance and best practices for container security. NIST SP 800-190
        ISO 27001: An international standard for information security management. ISO 27001
    Industry-Specific Frameworks: Additional regulations may apply, such as HIPAA for medical data.

Benchmarking:

    Definition: Assessing adherence to best practices and identifying areas for improvement.
    Tools:
        CIS Docker Benchmark: Assesses container compliance with CIS Docker Benchmark. CIS Docker Benchmark
        OpenSCAP: Assesses compliance with multiple frameworks, including CIS Docker Benchmark and NIST SP-800-190. OpenSCAP
        Docker Scout: Cloud-based service that scans Docker images for vulnerabilities. Docker Scout
        Anchore: Assesses compliance with multiple frameworks, including CIS Docker Benchmark and NIST SP-800-190. Anchore
        Grype: A modern and fast vulnerability scanner for Docker images. Grype

Example Usage:

    Docker Scout: Used to analyze Docker images for vulnerabilities and provide resolution steps. Documentation available for installation and use.

