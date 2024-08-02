Get to Know Your Toolkit

    IaC Tools:
        Examples: Terraform, AWS CloudFormation, Google Cloud Deployment Manager, Ansible, Puppet, Chef, SaltStack, Pulumi
        Often used in combination for end-to-end infrastructure management

    Declarative vs. Imperative:
        Declarative:
            Defines desired state for infrastructure
            Focuses on what needs to be achieved
            Idempotent (same result when run repeatedly)
            Examples: Terraform, AWS CloudFormation, Pulumi, Puppet, Ansible (supports declarative)
        Imperative:
            Defines specific commands to achieve desired state
            Focuses on how to achieve the desired state
            Not idempotent (may not produce the same result when run repeatedly)
            Examples: Chef, SaltStack, Ansible (supports imperative)

    Agent-based vs. Agentless:
        Agent-based:
            Requires installation of an agent on target systems
            Agents handle communication and task execution
            More granular control and detailed monitoring
            Higher maintenance and security considerations (e.g., open ports)
            Examples: Puppet, Chef, SaltStack
        Agentless:
            No agent installation required
            Uses existing protocols (SSH, WinRM, Cloud APIs)
            Easier setup and faster deployment
            Less control over target systems
            Examples: Terraform, AWS CloudFormation, Pulumi, Ansible

    Choosing the Right Tool:
        Depends on infrastructure needs and specific use cases
        Declarative tools are easier to manage long-term
        Imperative tools offer more flexibility and control
        Agent-based tools provide detailed control and monitoring
        Agentless tools offer simplicity and adaptability
