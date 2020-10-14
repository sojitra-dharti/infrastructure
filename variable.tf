variable "region" {
    type = string
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