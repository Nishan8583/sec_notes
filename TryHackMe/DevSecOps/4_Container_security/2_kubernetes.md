Kubernetes Architecture Overview

To fully grasp how Kubernetes functions in DevSecOps, let's delve into its architecture, breaking down each key component and understanding how they interconnect.
1. Kubernetes Pods

    Definition: The smallest deployable unit in Kubernetes.
    Composition: A group of one or more containers sharing storage and network resources.
    Communication: Containers within a pod can communicate as if they were on the same machine.
    Replication: Pods are treated as units of replication. Scaling a workload involves increasing the number of pods.

2. Kubernetes Nodes

    Workloads: Applications run inside containers, which are placed in pods on nodes.
    Types:
        Control Plane (Master Node): Manages the worker nodes and pods.
        Worker Nodes: Maintain running pods and host necessary services for pods.

3. Kubernetes Cluster

    Definition: A set of nodes working together to manage and run applications.

4. The Kubernetes Control Plane

    Function: Manages the worker nodes and pods in the cluster using several components.

Key Components of the Control Plane:

    Kube-apiserver:
        Role: Front end of the control plane.
        Function: Exposes the Kubernetes API.
        Scalability: Multiple instances can be created for load balancing.

    Etcd:
        Role: Key/value store containing cluster data.
        Function: Reflects the current state of the cluster, queried by other components for information such as available resources.

    Kube-scheduler:
        Role: Monitors the cluster for newly created pods.
        Function: Assigns pods to nodes based on resource availability and usage criteria.

    Kube-controller-manager:
        Role: Runs controller processes.
        Example: Node controller process, which notices when nodes go down and coordinates with the scheduler to bring up new nodes.

    Cloud-controller-manager:
        Role: Enables communication between the Kubernetes cluster and cloud provider APIs.
        Function: Separates internal cluster communication from external cloud provider interactions, allowing independent feature releases.

5. Kubernetes Worker Node

    Role: Maintains running pods and hosts components necessary for pod management.

Key Components of Worker Nodes:

    Kubelet:
        Role: Ensures containers are running in a pod.
        Function: Executes actions given by the controller manager, ensuring container health and pod specifications.

    Kube-proxy:
        Role: Manages network communication within the cluster.
        Function: Creates networking rules to direct traffic to pods via Services, which route traffic to associated pods.

    Container Runtime:
        Role: Runs containers inside pods.
        Examples: Docker (most popular), rkt, runC.

6. Communication Between Components

    Control Plane to Nodes: The control plane communicates with nodes to manage and maintain the state of the cluster, ensuring containers are running as specified and handling network routing.

Putting It All Together

A Kubernetes cluster orchestrates containerized applications by distributing them across multiple nodes. The control plane manages this orchestration by assigning workloads to nodes, monitoring the health and status of these workloads, and ensuring seamless network communication. Worker nodes execute and maintain the containers, ensuring that applications run efficiently and securely.

In DevSecOps, understanding this architecture is crucial for effectively deploying, managing, and securing containerized applications using Kubernetes.
