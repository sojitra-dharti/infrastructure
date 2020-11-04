# Infrastructure as Code with Terraform

* Created a terraform configuration file that can to setup all the networking resources.
* Terraform configuration files is designed to create multiple VPCs including all of it resources such as subnets, internet gateway, route table, etc.
* Terraform apply will launch latest instance, create RDS instance, create and attach all policies related to S3 bucket and S3 user.
* Terraform template should add/update the DNS record.


**Environment variables/Github Secrets**

1. `region`
2. `availabilityZone`
3. `subnetCIDRblock`
4. `vpcCIDRblock`
5. `destinationCIDRblock`
6. `vpc_name`
7. `ingressCIDRblock`
8. `egressCIDRblock`
9. `rdsDBName`
10. `rdsUsername`
11. `rdsPassword`
12. `rdsInstanceIdentifier`
13. `engine_version`
14. `instance_type`
15. `my_key`
16. `ec2_root_volume_size`
17. `ec2_root_volume_type`
18. `image_id`
19. `dynamo_tablename`
20. `policy_WebAppS3`
21. `iamrole`
22. `dev_owner`
23. `domainName`
24. `routeprofile`

**Command for building terraform**

1. `terraform validate -var-file="sensitive.tfvars"`  
2. `terraform apply -var-file="sensitive.tfvars"` 
3. `terraform destroy`

**Terraform workspaces**
*   Teraaform workdspaces used to create muliple network resources using same configuration files.
*   terraform workspace <subcommand> [options] [args]
1. `terraform workspace` to check all commands.
2. `terraform workspace new [NAME]` to create new workspace.
3.  Use apply command in newly created workspace.
4. `terraform workspace show` to check current workspace.
4. `terraform workspace select [NAME]` to switch between workspaces.

**Download Terraform**

[Download Terraform](https://www.terraform.io/downloads.html)
