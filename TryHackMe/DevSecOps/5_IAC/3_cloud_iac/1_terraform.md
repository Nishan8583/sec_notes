# Terraform Overview

Terraform is an infrastructure as code (IaC) tool used for provisioning, allowing users to define both cloud and on-prem resources in a human-readable configuration file. These configuration files can be versioned, reused, and distributed across teams. Terraform uses a consistent workflow to make infrastructure management easy and reliable.

## Key Concepts

### Terraform Provisioning
- Allows definition and management of infrastructure resources.
- Uses human-readable configuration files.
- Supports versioning, reuse, and team distribution.

### Terraform Architecture

#### Terraform Core
- **Function**: Core functionalities for provisioning and managing infrastructure.
- **Declarative Tool**: Ensures infrastructure meets the desired state defined in configuration files.
- **Inputs**:
  - **Terraform Config Files**: Defines the desired state of infrastructure.
  - **State File (`terraform.tfstate`)**: Tracks the current state of provisioned infrastructure.

#### Workflow
- **Comparison**: Core checks state file against desired state in config files.
- **Planning**: Creates a plan to transition from the current state to the desired state.
- **Execution**: Uses providers to execute the plan and provision resources.

### Providers
- **Role**: Interact with cloud providers, SaaS providers, and other APIs.
- **Examples**:
  - AWS Provider for AWS resources (e.g., EC2 instances).
  - Kubernetes Provider for Kubernetes clusters.

### Benefits for DevSecOps
- **Multi-cloud Support**: Manages resources across multiple cloud providers (e.g., AWS, Azure).
- **Prevents Vendor Lock-in**: Enhances infrastructure flexibility.
- **Declarative Configuration Language**: 
  - Easy to understand and human-readable.
  - Simplifies resource definition.
  - Supports versioning and change-tracking.
- **Collaboration**: Facilitates team collaboration and rollback to previous infrastructure iterations.

## Example Configuration

```hcl
provider "aws" {
  region = "us-west-2"
}

resource "aws_instance" "example" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  tags = {
    Name = "example-instance"
  }
}
