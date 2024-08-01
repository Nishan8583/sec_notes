### Access
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

### Implementing Control Groups
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
