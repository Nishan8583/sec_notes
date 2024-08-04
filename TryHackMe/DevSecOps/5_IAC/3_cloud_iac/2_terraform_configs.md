# Configuration & Terraform

Now that we know what Terraform is and how it works, let's take a look at how we define the desired state using Terraform config files. Terraform config files are written in a declarative language called HCL (HashiCorp Configuration Language), which is easy to understand and human-readable. The primary purpose of this language is to declare resources, which represent infrastructure objects. The combined definition of these resources makes up the desired infrastructure state.

## Defining a Simple VPC

### AWS Provider and VPC Resource

```hcl
provider "aws" {
  region = "eu-west-2"
}

# Create a VPC
resource "aws_vpc" "flynet_vpc" {
  cidr_block = "10.0.0.0/16"
  tags = {
    Name = "flynet-vpc"
  }
}
```
Explanation:

    Provider Block: Defines AWS as the provider.
    Resource Block: Defines an AWS VPC named "flynet_vpc" with a specified CIDR block and tags for identification

### Resource Relationships
AWS Security Group with Ingress Rule
```hcl
resource "aws_security_group" "example_security_group" {
  name        = "example-security-group"
  description = "Example Security Group"
  vpc_id      = aws_vpc.flynet_vpc.id

  # Ingress rule allowing SSH access from any source within the VPC
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.flynet_vpc.cidr_block]
  }
}

```
Explanation:

    Resource Block: Defines an AWS security group allowing SSH access within the VPC.
    Resource Reference: Uses the VPC ID and CIDR block from the previously defined VPC.

### Infrastructure Modularization
Modular Configuration

Terraform allows for the modularization of infrastructure, breaking down complex configurations into modular components. This is common in large organizations to simplify management.
Directory Structure
```
tfconfig/
├── flynet_vpc_security.tf # Defines security-related resources
├── other_module.tf # Defines other resources
├── variables.tf # Parameterizes commonly used values
└── main.tf # Central configuration file referencing modules
```
### Example Configuration
variables.tf

```hcl
variable "vpc_cidr_block" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}
```

Explanation:

    Variable Block: Defines a variable for the VPC CIDR block, making it reusable across multiple modules.

### flynet_vpc_security.tf
```hcl
cidr_block = var.vpc_cidr_block
```
Explanation:

    Variable Reference: Uses the vpc_cidr_block variable defined in variables.tf.


### main.tf
```hcl
module "flynet_vpc_security" {
  source = "./flynet_vpc_security.tf"
}

module "other_module" {
  source = "./other_module.tf"
}
```

Explanation:

    Module Block: References the modular files to create a cohesive infrastructure setup.

This modular approach is beneficial for managing complex infrastructure configurations, promoting reuse and maintainability.
