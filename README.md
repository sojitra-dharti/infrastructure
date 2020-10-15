# Infrastructure as Code with Terraform

* Created a terraform configuration file that can to setup all the networking resources.
* Terraform configuration files is designed to create multiple VPCs including all of it resources such as subnets, internet gateway, route table, etc.

**Environment variables/Github Secrets**

1. `region`
2. `availabilityZone`
3. `subnetCIDRblock`
4. `vpcCIDRblock`
5. `destinationCIDRblock`
6. `vpc_name`

**Command for building terraform**

1. `terraform validate -var-file="sensitive.tfvars"`  
2. `terraform apply -var-file="sensitive.tfvars"` 
3. `terraform destroy`

**Terraform workspaces**
*   Teraaform workdspaces used to create muliple network resources using same configuration files.
1. `terraform workspace` to check all commands.
2. `terraform new [workspacename]` to create new workspace.
3.  Use apply command in newly created workspace.
4. `terraform show` to check current workspace.
4. `terraform select [workspacename]` to switch between workspaces.

**Download Terraform**

[Download Terraform](https://www.terraform.io/downloads.html)
