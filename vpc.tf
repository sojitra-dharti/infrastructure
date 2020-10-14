# vpc.tf 
# Select providers
provider "aws" {
 profile= "dev"
 region= var.region 
}

# create the User VPC
resource "aws_vpc" "User_VPC" {
  cidr_block           = var.vpcCIDRblock
  instance_tenancy     = var.instanceTenancy 
  enable_dns_support   = var.dnsSupport 
  enable_dns_hostnames = var.dnsHostNames
tags = {
    Name = "${var.vpc_name}"
}
} # end resource

# create the Subnet for the newly created VPC
resource "aws_subnet" "User_VPC_Subnet" {
  count                   = "${length(var.subnetCIDRblock)}"
  vpc_id                  = aws_vpc.User_VPC.id
  cidr_block              = "${var.subnetCIDRblock[count.index]}"
  map_public_ip_on_launch = var.mapPublicIP 
  availability_zone       = "${var.availabilityZone[count.index]}"
tags = {
   Name = "${var.vpc_name} Subnet - ${count.index}"
}
} # end resource


# Create the Internet Gateway
resource "aws_internet_gateway" "User_VPC_GW" {
 vpc_id = aws_vpc.User_VPC.id
 tags = {
        Name = "User VPC Internet Gateway"
}
} # end resource



# Create the Route Table
resource "aws_route_table" "User_VPC_route_table" {
 vpc_id = aws_vpc.User_VPC.id
 tags = {
        Name = "User VPC Route Table"
}
} # end resource
# Create the Internet Access
resource "aws_route" "User_VPC_internet_access" {
  route_table_id         = aws_route_table.User_VPC_route_table.id
  destination_cidr_block = var.destinationCIDRblock
  gateway_id             = aws_internet_gateway.User_VPC_GW.id
} # end resource

# Associate the Route Table with the Subnet
resource "aws_route_table_association" "User_VPC_association" {
  count          = "${length(var.subnetCIDRblock)}"
  subnet_id      = "${element(aws_subnet.User_VPC_Subnet.*.id, count.index)}"
  route_table_id =  aws_route_table.User_VPC_route_table.id
} # end resource
# end vpc.tf