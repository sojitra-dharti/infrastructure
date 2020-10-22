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
  #storage_type         = "gp2"
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

  # DB subnet group
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
               sudo echo export "DevAccessKey=${var.DevAccessKey}" >> /etc/environment
               sudo echo export "DevSecretKey=${var.DevSecretKey}" >> /etc/environment
               sudo echo export "Bucketname=${aws_s3_bucket.bucket.bucket}" >> /etc/environment
               sudo echo export "DBhost=${aws_db_instance.My_RDS_Instance.address}" >> /etc/environment
               sudo echo export "DBendpoint=${aws_db_instance.My_RDS_Instance.endpoint}" >> /etc/environment
               sudo echo export "DBname=${var.rdsDBName}" >> /etc/environment
               sudo echo export "DBusername=${aws_db_instance.My_RDS_Instance.username}" >> /etc/environment
               sudo echo export "DBpassword=${aws_db_instance.My_RDS_Instance.password}" >> /etc/environment
               EOF
  tags = {
    Name        = "Application Server"
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
                "s3:*"
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