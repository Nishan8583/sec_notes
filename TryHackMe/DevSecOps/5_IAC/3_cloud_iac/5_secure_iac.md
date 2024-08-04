# Secure Cloud IaC Best Practices

For Both CloudFormation and Terraform
=====================================

## General Best Practices

* **Version Control**: Store IaC code in version control systems like Git to track changes, facilitate collaboration, and maintain a version history.
* **Least Privilege Principle**: Always assign the least permissions and scope for credentials and IaC tools. Only grant the needed permissions for the actions to be performed.
* **Parameterise Sensitive Data**: Use parameterisation to handle credentials or API keys and avoid hardcoding secrets directly into the IaC code.
* **Secure Credential Management**: Leverage the cloud platform's secure credential management solutions or services to securely handle and store sensitive information, e.g., vaults for secret management.
* **Audit Trails**: Enable logging and monitoring features to maintain an audit trail of changes made through IaC tools. Use these logs to conduct reviews periodically.
* **Code Reviews**: Implement code reviews to ensure IaC code adheres to best security practices. Collaborative review processes can catch potential security issues early.

## AWS CloudFormation

### Best Practices

* **Use IAM Roles**: Assign Identity and Access Management (IAM) roles with the minimum required permissions to CloudFormation stacks. Avoid using long-term access keys when possible.
* **Secure Template Storage**: Store CloudFormation templates in an encrypted S3 bucket and restrict access to only authorised users or roles.
* **Stack Policies**: Implement stack policies to control updates to stack resources and enforce specific conditions during updates.

## Terraform

### Best Practices

* **Backend State Encryption**: Enable backend state encryption to protect sensitive information stored in the Terraform state file.
* **Use Remote Backends**: Store the Terraform state remotely using backends like Amazon S3 or Azure Storage. This enhances collaboration and provides better security.
* **Variable Encryption**: Consider encrypting sensitive values using tools like HashiCorp Vault or other secure key management solutions when using variables.
* **Provider Configuration**: Securely configure provider credentials using environment variables, variable files, or other secure methods.

Check out the [Source Code Security room](link-to-room) to learn more about this area.
