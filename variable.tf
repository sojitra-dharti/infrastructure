variable "region" {
    type = string
}
variable "profile" {
    type = string
}
variable "DevAccessKey" {
   type=string
}
variable "DevSecretKey" {
   type=string
}
variable "vpc_name" {
   type=string
}
variable "availabilityZone" {
     type=list
}
variable "instanceTenancy" {
    default = "default"
}
variable "dnsSupport" {
    default = true
}
variable "dnsHostNames" {
    default = true
}
variable "vpcCIDRblock" {
    type=string
}
variable "subnetCIDRblock" {
    type=list
}
variable "destinationCIDRblock" {
    type=string
}
variable "mapPublicIP" {
    default = true
}
variable "s3bucketname" {
    type = string
}


## Security groups

variable "ingressCIDRblock" {
    type = list
}
variable "egressCIDRblock" {
    type = list
}

## RDS INSTANCE

variable "rdsDBName" {
   type=string
}
variable "rdsUsername" {
   type=string
}
variable "rdsPassword" {
   type=string
}
variable "rdsInstanceIdentifier" {
   type=string
}
variable "engine_version"{
   type=string
}

## EC2 instance

variable "instance_type"{
type=string

}
variable "my_key"{
 type=string
}

variable "ec2_root_volume_size"{
 type=string
}

variable "ec2_root_volume_type"{
 type=string
}

variable "image_id" {
  type = string
}

## DynamoDB Table
variable "dynamo_tablename" {
  type = string
}

## policy for s3
variable "policy_WebAppS3" {
  type = string
}

## IAM role
variable "iamrole" {
  type = string
}

variable "dev_owner"{
type=string
}
