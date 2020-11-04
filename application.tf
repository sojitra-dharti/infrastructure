## S3 bucket ##

resource "aws_s3_bucket" "bucket" {
  bucket        = "${var.s3bucketname}"
  acl           = "private"
  force_destroy = "true"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }

  lifecycle_rule {
    enabled = true

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }
}



## Application Security Group ##
resource "aws_security_group" "application" {
  name        = "application"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.User_VPC.id

  ingress {
    description = "TLS from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.ingressCIDRblock

  }
  ingress {
    description = "TLS from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.ingressCIDRblock

  }
  ingress {
    description = "TLS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.ingressCIDRblock

  }
  ingress {
    description = "TLS from VPC"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = var.ingressCIDRblock

  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Application Security Group"
  }
}

## Database Group ##
resource "aws_security_group" "database" {
  name        = "database_security_group"
  description = "Allow TLS inbound traffic"
  vpc_id      = aws_vpc.User_VPC.id

  ingress {
    description = "MYSQL"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    security_groups = ["${aws_security_group.application.id}"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1" # means all ports
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Database Security Group"
  }
}

# RDS instance setup
resource "aws_db_instance" "My_RDS_Instance" {
  allocated_storage = 5
  storage_type         = "gp2"
  name              = "${var.rdsDBName}"
  username          = "${var.rdsUsername}"
  password          = "${var.rdsPassword}"
  identifier        = "${var.rdsInstanceIdentifier}"
  engine            = "mysql"
  engine_version    = "${var.engine_version}"
  instance_class    = "db.t3.micro"
  storage_encrypted = true
  port              = "3306"

  final_snapshot_identifier = "${var.rdsInstanceIdentifier}-SNAPSHOT"
  skip_final_snapshot       = true
  publicly_accessible       = false
  multi_az                  = false

  tags = {
    Name = "csye6225"
  }

#   # DB subnet group
  db_subnet_group_name   = "${aws_db_subnet_group.rds_subnet.name}"
  vpc_security_group_ids = ["${aws_security_group.database.id}"]
}


## EC2 instance 
resource "aws_instance" "webapp" {
  instance_type          = "${var.instance_type}"
  vpc_security_group_ids = ["${aws_security_group.application.id}"]
  subnet_id              = "${aws_subnet.User_VPC_Subnet[2].id}"
  ami                    = data.aws_ami.ami.id
  key_name               = "${var.my_key}"
  depends_on             = [aws_db_instance.My_RDS_Instance]
  iam_instance_profile = "${aws_iam_instance_profile.ec2_profile.name}"
  user_data = <<-EOF
               #!/bin/bash
               
               sudo echo export "Bucketname=${aws_s3_bucket.bucket.bucket}" >> /etc/environment
               sudo echo export "DBhost=${aws_db_instance.My_RDS_Instance.address}" >> /etc/environment
               sudo echo export "DBendpoint=${aws_db_instance.My_RDS_Instance.endpoint}" >> /etc/environment
               sudo echo export "DBname=${var.rdsDBName}" >> /etc/environment
               sudo echo export "DBusername=${aws_db_instance.My_RDS_Instance.username}" >> /etc/environment
               sudo echo export "DBpassword=${aws_db_instance.My_RDS_Instance.password}" >> /etc/environment
               EOF
  root_block_device {
    volume_size           = "${var.ec2_root_volume_size}"
    volume_type           = "${var.ec2_root_volume_type}"
      }
  tags = {
    Name        = "UserEC2Instance"
    Environment = "Developments"
  }
}
data "aws_ami" "ami"{
  most_recent = true
  owners = [var.dev_owner]
}

resource "aws_db_subnet_group" "rds_subnet" {
  name = "database_subnet_group"
  subnet_ids = ["${aws_subnet.User_VPC_Subnet[0].id}", "${aws_subnet.User_VPC_Subnet[1].id}"]

  tags = {
    Name = "My DB subnet group"
  }
}



#Dynamo db table
resource "aws_dynamodb_table" "basic-dynamodb-table" {
  name           = var.dynamo_tablename
  read_capacity  = 5
  write_capacity = 5
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }

  tags = {
    Name        = "dynamodb table"
    Environment = "development"
  }
}

# IAM Policy for S3 bucket

resource "aws_iam_policy" "policy" {
  name        = var.policy_WebAppS3
  path        = "/"
  description = "WebAppS3 policy"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "s3:PutObject",
                "s3:Get*",
                "s3:List*",
                "s3:DeleteObject",
                "s3:DeleteObjectVersion"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:s3:::${var.s3bucketname}",
                "arn:aws:s3:::${var.s3bucketname}/*"
            ]
        }
    ]
}
EOF
}


resource "aws_iam_role" "role" {
  name = var.iamrole

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "WebAppS3-IAM-attach" {
  role       = aws_iam_role.role.name
  policy_arn = aws_iam_policy.policy.arn
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2_profile_role"
  role = "${aws_iam_role.role.name}"
}

# This Policy is for EC2 Role 
resource "aws_iam_role_policy" "CodeDeploy-EC2-S3" {
  name = "ec2_policy"
  role = "${aws_iam_role.role.id}"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:Get*"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:s3:::codedeploy.${var.routeprofile}.${var.domainName}/*",
        "arn:aws:s3:::webapp.${var.routeprofile}.${var.domainName}/*"
      ]
    }
  ]
}
EOF
}

resource "aws_iam_policy" "GH-Upload-To-S3" {
  name = "GH-Upload-To-S3_policy"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:Get*",
        "s3:List*",
        "s3:DeleteObject",
        "s3:DeleteObjectVersion"
        ],
      "Resource":[ 
        "arn:aws:s3:::codedeploy.${var.routeprofile}.${var.domainName}",
        "arn:aws:s3:::codedeploy.${var.routeprofile}.${var.domainName}/*"
      ]
    }
  ]
}
EOF
}

data "aws_caller_identity" "current" {}
locals {
  # Ids for multiple sets of EC2 instances, merged together
  account_id = "${data.aws_caller_identity.current.account_id}"
}

resource "aws_iam_policy" "GH-Code-Deploy" {
  name = "GH_Code_Deploy_policy"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:RegisterApplicationRevision",
        "codedeploy:GetApplicationRevision"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.region}:${local.account_id}:application:${aws_codedeploy_app.code_deploy_app.name}"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:CreateDeployment",
        "codedeploy:GetDeployment"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.region}:${local.account_id}:deploymentgroup:${aws_codedeploy_app.code_deploy_app.name}/${aws_codedeploy_deployment_group.code_deploy_deployment_group.deployment_group_name}"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:GetDeploymentConfig"
      ],
      "Resource": [
       "arn:aws:codedeploy:${var.region}:${local.account_id}:deploymentconfig:CodeDeployDefault.OneAtATime",
       "arn:aws:codedeploy:${var.region}:${local.account_id}:deploymentconfig:CodeDeployDefault.HalfAtATime",
       "arn:aws:codedeploy:${var.region}:${local.account_id}:deploymentconfig:CodeDeployDefault.AllAtOnce"
      ]
    }
  ]
}
EOF
}

resource "aws_iam_policy" "gh-ec2-ami" {
  name = "gh-ec2-ami_policy"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:AttachVolume",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:CopyImage",
        "ec2:CreateImage",
        "ec2:CreateKeypair",
        "ec2:CreateSecurityGroup",
        "ec2:CreateSnapshot",
        "ec2:CreateTags",
        "ec2:CreateVolume",
        "ec2:DeleteKeyPair",
        "ec2:DeleteSecurityGroup",
        "ec2:DeleteSnapshot",
        "ec2:DeleteVolume",
        "ec2:DeregisterImage",
        "ec2:DescribeImageAttribute",
        "ec2:DescribeImages",
        "ec2:DescribeInstances",
        "ec2:DescribeInstanceStatus",
        "ec2:DescribeRegions",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSnapshots",
        "ec2:DescribeSubnets",
        "ec2:DescribeTags",
        "ec2:DescribeVolumes",
        "ec2:DetachVolume",
        "ec2:GetPasswordData",
        "ec2:ModifyImageAttribute",
        "ec2:ModifyInstanceAttribute",
        "ec2:ModifySnapshotAttribute",
        "ec2:RegisterImage",
        "ec2:RunInstances",
        "ec2:StopInstances",
        "ec2:TerminateInstances"
      ],
      "Resource": "*"
    }
  ]
}
EOF
}


resource "aws_iam_user_policy_attachment" "GH_Upload_To_S3_policy_attach" {
  user = "ghactions"
  policy_arn = "${aws_iam_policy.GH-Upload-To-S3.arn}"
}

resource "aws_iam_user_policy_attachment" "GH_Code_Deploy_policy_attach" {
  user = "ghactions"
  policy_arn = "${aws_iam_policy.GH-Code-Deploy.arn}"
}

resource "aws_iam_user_policy_attachment" "gh_ec2_ami_policy_attach" {
  user = "ghactions"
  policy_arn = "${aws_iam_policy.gh-ec2-ami.arn}"
}



#Create CodeDeployEC2ServiceRole IAM Role for EC2 Instance(s)
resource "aws_iam_role" "CodeDeployServiceRole" {
  name = "CodeDeployServiceRole"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "codedeploy.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

# Attach the policy for CodeDeploy role for webapp
resource "aws_iam_role_policy_attachment" "AWSCodeDeployRole" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
  role       = "${aws_iam_role.CodeDeployServiceRole.name}"
}



#CodeDeploy App and Group for webapp
resource "aws_codedeploy_app" "code_deploy_app" {
  compute_platform = "Server"
  name             = "csye6225-webapp"
}

resource "aws_codedeploy_deployment_group" "code_deploy_deployment_group" {
  app_name              = "${aws_codedeploy_app.code_deploy_app.name}"
  deployment_group_name = "csye6225-webapp-deployment"
  deployment_config_name = "CodeDeployDefault.AllAtOnce"
  service_role_arn      = "${aws_iam_role.CodeDeployServiceRole.arn}"
 

  ec2_tag_filter {
    key   = "Name"
    type  = "KEY_AND_VALUE"
    value = "UserEC2Instance"
  }

  deployment_style {
    deployment_option = "WITHOUT_TRAFFIC_CONTROL"
    deployment_type   = "IN_PLACE"
  }

  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }
  depends_on = [aws_codedeploy_app.code_deploy_app]
}

data "aws_route53_zone" "selected" {
  name         = "${var.routeprofile}.${var.domainName}"
  private_zone = false
}

resource "aws_route53_record" "www" {
  zone_id = data.aws_route53_zone.selected.zone_id
  name    = "api.${data.aws_route53_zone.selected.name}"
  type    = "A"
  ttl     = "300"
  records = ["${aws_instance.webapp.public_ip}"]
}