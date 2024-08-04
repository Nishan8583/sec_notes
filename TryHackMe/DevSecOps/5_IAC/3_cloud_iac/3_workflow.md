# Understanding the Terraform Workflow

The Terraform workflow generally follows four steps: Write, Initialize, Plan, and Apply. To better understand this workflow and how it benefits DevSecOps engineers during infrastructure provisioning, let's consider infrastructure at different stages of development: Day 1, Day 2+, and Day N.

## Day 1: Provisioning from Scratch

### Write
- Define the desired state of your infrastructure in a Terraform configuration file.
- Configuration files specify the desired components and their relationships.

### Initialize
- Prepares your workspace (working directory with Terraform configuration files).
- Downloads necessary dependencies, such as provider plugins.
- Command: `terraform init`

### Plan
- Compares current infrastructure (none on Day 1) to the desired state.
- Produces an execution plan detailing actions to match the desired state.
- Command: `terraform plan`

### Apply
- Executes the plan to transition from the current state to the desired state.
- Creates resources in the correct order based on dependencies.
- Command: `terraform apply`

## Day 2+: Making Changes to Existing Infrastructure

### Initialize
- Run `terraform init` after making changes to the configuration to initialize the workspace.

### Plan
- Generates an execution plan to show changes (additions/removals) to the existing infrastructure.
- Helps catch misconfigurations before applying changes.
- Command: `terraform plan` (optional but recommended)

### Apply
- Provisions the changes defined in the execution plan.
- Updates the state file to reflect the current state matching the desired state.
- Command: `terraform apply`

## Day N: Destroying Infrastructure

### Destroy
- Takes a plan to tear down all resources, removing the infrastructure.
- Command: `terraform destroy`

## Terraform Workflow Summary

1. **Write**: Define infrastructure in configuration files.
2. **Initialize**: Prepare workspace and download dependencies.
   - Command: `terraform init`
3. **Plan**: Generate an execution plan to preview changes.
   - Command: `terraform plan`
4. **Apply**: Execute the plan to provision infrastructure.
   - Command: `terraform apply`
5. **Destroy**: Remove all infrastructure resources.
   - Command: `terraform destroy`
