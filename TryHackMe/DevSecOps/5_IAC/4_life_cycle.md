The Infrastructure as Code Lifecycle (IaCLC)

The IaC lifecycle (IaCLC) provides a structured approach to provisioning, managing, and evolving infrastructure through code. It encompasses continual best practices and repeatable phases, ensuring a robust and adaptable infrastructure management process.
Continual (Best Practice) Phases

These phases are ongoing processes that ensure best practices are followed throughout the lifecycle. They can trigger repeatable phases as needed.

    Version Control:
        Versioning infrastructure code allows for tracking changes and facilitates rollbacks if new changes cause issues.
        Tools: Git, GitHub, GitLab, Bitbucket

    Collaboration:
        Effective communication and teamwork are crucial for maintaining a cohesive infrastructure.
        Tools: Slack, Microsoft Teams, Confluence, Jira

    Monitoring/Maintenance:
        Continuous monitoring of infrastructure for performance, security events, failures, and warnings is essential.
        Automated maintenance tasks can help mitigate some issues.
        Tools: Prometheus, Grafana, Nagios, Datadog

    Rollback:
        In the event of a failure, rollback to the last known working version of the infrastructure.
        This phase is often triggered by monitoring/maintenance.

    Review + Change:
        Regular reviews to assess efficiency, security, and business requirements.
        Implement changes as needed to improve infrastructure.

Repeatable (Infra Creation + Config) Phases

These phases are performed during the creation and configuration of infrastructure and can be repeated as needed.

    Design:
        Design infrastructure based on requirements, ensuring security and scalability.
        Consider potential issues like poor scaling policies that could affect availability.

    Define:
        Use the design to define the infrastructure in code.
        Tools: Terraform, AWS CloudFormation, Pulumi

    Test:
        Validate code using linters and testing in a staging environment to catch syntax errors and logical issues.
        Tools: Terraform validate, InSpec, Testinfra

    Provision:
        Provision the infrastructure in the production environment.
        Tools: Terraform, AWS CloudFormation, Pulumi

    Configure:
        Configure the provisioned infrastructure using configuration management tools.
        Tools: Ansible, Chef, Puppet, SaltStack

Connecting the Phases
Continual Phase Block

Continual phases ensure that best practices are followed throughout the lifecycle. They are ongoing and provide a stable foundation for infrastructure management.
Trigger Block

Continual phases can trigger repeatable phases as needed. For example, monitoring might trigger a rollback or a review phase might trigger a design and define phase to implement changes.
Repeatable Phase Block

Repeatable phases handle the actual creation and configuration of infrastructure. They are performed as needed and can vary depending on the specific requirements of the task.
