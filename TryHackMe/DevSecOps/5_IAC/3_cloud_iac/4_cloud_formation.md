# CloudFormation Overview

## Declarative Infrastructure as Code
CloudFormation allows you to describe your AWS infrastructure using JSON or YAML templates. These templates express the desired state of your resources, which CloudFormation then provisions and manages automatically.

## Templates and Stacks
- **Template**: A blueprint for your infrastructure.
- **Stack**: A collection of AWS resources defined by a template.

### Example Template
```yaml
AWSTemplateFormatVersion: '2010-09-09'
Description: 'A simple CloudFormation template'
Resources:
  MyEC2Instance:
    Type: 'AWS::EC2::Instance'
    Properties:
      ImageId: 'ami-12345678'
      InstanceType: 't2.micro'
      KeyName: 'my-key-pair'
  MyS3Bucket:
    Type: 'AWS::S3::Bucket'
    Properties:
      BucketName: 'my-s3-bucket'
Outputs:
  EC2InstanceId:
    Description: 'ID of the EC2 instance'
    Value: !Ref MyEC2Instance
```
    AWSTemplateFormatVersion: Specifies the template version.
    Description: Brief description of the template.
    Resources: Defines AWS resources, with logical names, types, and properties.
    Outputs: Defines output values displayed after creating the stack.

CloudFormation Designer

    A visual tool for creating and validating templates.

CloudFormation Architecture
Main and Worker Architecture

    Main Node: Processes templates and manages stack operations.
    Worker Nodes: Provision resources across AWS regions.

Template Processing Flow

    Template Submission: Submit a JSON or YAML template to CloudFormation.
    Template Validation: CloudFormation checks the template syntax and resource specifications.
    Processing by Main Node: Creates instructions for resource provisioning.
    Resource Provisioning: Worker nodes provision resources based on instructions.
    Stack Creation/Update: Resources are created or updated to form a stack.

Event-Driven Model

    Logs events during stack operations for monitoring and troubleshooting.

Rollback and Rollback Triggers

    Automatically reverts to the previous state if errors occur during stack creation or updates.
    Rollback triggers can be defined in the template.

Cross-Stack References

    Allows resources in one stack to refer to resources in another, useful for complex applications and dependencies.
