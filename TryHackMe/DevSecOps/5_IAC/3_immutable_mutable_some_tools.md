Immutable vs. Mutable Infrastructure

    Mutable Infrastructure:
        Changes can be made in place (e.g., updating application on the current server)
        No need for additional resources for updates
        Issues can arise if updates partially fail, leading to inconsistent states
        Suitable for scenarios needing regular maintenance (e.g., critical databases)

    Immutable Infrastructure:
        No changes allowed once provisioned; new infrastructure is deployed for updates
        Ensures consistency across servers
        Resource-intensive due to multiple infrastructures existing simultaneously or retrying failed attempts
        Suitable for applications requiring consistency and reliability

    Examples:
        Immutable IaC tools: Terraform, AWS CloudFormation, Google Cloud Deployment Manager, Pulumi

Provisioning vs. Configuration Management

    Provisioning Tools:
        Used for setting up infrastructure
        Examples: Terraform, AWS CloudFormation, Google Cloud Deployment Manager, Pulumi

    Configuration Management Tools:
        Used for managing infrastructure changes, software installation, and updates
        Examples: Ansible, Chef, Puppet, SaltStack

    Combined Use:
        Common practice to use provisioning tools for initial setup and configuration management tools for ongoing management
        Example: Use Terraform for provisioning and Ansible for installing monitoring agents

Tool Characteristics and Use Cases

    Terraform:
        Declarative, agentless, immutable infrastructure provisioning
        Popular for managing infrastructure across multiple cloud providers

    Ansible:
        Hybrid, typically agentless, configuration management
        Works with mutable infrastructure
        Flexible and adaptable based on usage

    Pulumi:
        Declarative, agentless, immutable infrastructure provisioning
        Allows defining infrastructure using general-purpose languages (Python, JavaScript, Go, Java, YAML)

    AWS CloudFormation:
        Declarative, agentless, immutable infrastructure provisioning for AWS
        Uses JSON/YAML templates

    Chef:
        Imperative, agent-based, mutable infrastructure configuration management
        Uses "Recipes" and "Cookbooks" for defining and automating desired states

    Puppet:
        Declarative, agent-based, mutable infrastructure configuration management
        Uses Puppet Code (DSL) for defining desired configuration states
