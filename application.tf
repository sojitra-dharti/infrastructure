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
    //security_groups = ["${aws_security_group.loadbalancer_security_group.id}"]

  }
  ingress {
    description = "TLS from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    security_groups = ["${aws_security_group.loadbalancer_security_group.id}"]

  }
  ingress {
    description = "TLS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    security_groups = ["${aws_security_group.loadbalancer_security_group.id}"]

  }
  ingress {
    description = "TLS from VPC"
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    security_groups = ["${aws_security_group.loadbalancer_security_group.id}"]

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

resource "aws_iam_role_policy_attachment" "CloudWatchAgentPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
  role       = "${aws_iam_role.role.name}"
}


resource "aws_iam_role_policy_attachment" "AmazonSSMManagedInstanceCore" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  role       = "${aws_iam_role.role.name}"
}

resource "aws_db_parameter_group" "rds" {
  name   = "rds-pg"
  family = "mysql5.7"
  

  parameter {
    name  = "performance_schema"
    value = 1
    apply_method = "pending-reboot"
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
  instance_class    = "db.t2.small"
  storage_encrypted = true
  port              = "3306"
  parameter_group_name = "${aws_db_parameter_group.rds.name}"
  depends_on = [aws_db_parameter_group.rds]
  
  

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
resource "aws_launch_configuration" "asg_launch_config" {
  name                   ="asg_launch_config"
  instance_type          = "${var.instance_type}"
  security_groups        = ["${aws_security_group.application.id}"]
  //subnet_id              = "${aws_subnet.User_VPC_Subnet[2].id}"
  image_id                    = data.aws_ami.ami.id
  associate_public_ip_address = true
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
               sudo echo export "Domain=${var.routeprofile}.${var.domainName}" >> /etc/environment
               sudo echo export "sns_topic_arn=${aws_sns_topic.sns_topics.arn}" >> /etc/environment

               EOF
  root_block_device {
    volume_size           = "${var.ec2_root_volume_size}"
    volume_type           = "${var.ec2_root_volume_type}"
      }
  # tags = {
  #   Name        = "UserEC2Instance"
  #   Environment = "Developments"
  # }
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
  hash_key       = "email_id"

  attribute {
    name = "email_id"
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

#IAM role attached to EC2 instance for use with CloudWatch Agent



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
  autoscaling_groups = ["${aws_autoscaling_group.awsAutoscalingGroup.name}"]

  ec2_tag_filter {
    key   = "Name"
    type  = "KEY_AND_VALUE"
    value = "myEC2Instance"
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
  name    = "${data.aws_route53_zone.selected.name}"
  type    = "A"
  # ttl     = "60"
  # records = ["${aws_launch_configuration.example.public_ip}"]
   alias {
    name    = "${aws_lb.WebappLoadbalancer.dns_name}"
    zone_id = "${aws_lb.WebappLoadbalancer.zone_id}"
    evaluate_target_health = true
  }
}


  # Aws Autoscaling Group Settings
resource "aws_autoscaling_group" "awsAutoscalingGroup" {
  name                 = "awsAutoscalingGroup"
  launch_configuration = "${aws_launch_configuration.asg_launch_config.name}"
  min_size             = 3
  max_size             = 5
  default_cooldown     = 60
  desired_capacity     = 3
  vpc_zone_identifier = ["${aws_subnet.User_VPC_Subnet[0].id}"]# can be array
  target_group_arns = ["${aws_lb_target_group.LoadBalancer-target-group.arn}"]
  tag {
    key                 = "Name"
    value               = "myEC2Instance"
    propagate_at_launch = true
  }
}

resource "aws_lb_target_group" "LoadBalancer-target-group" {
  name     = "LoadBalancer-target-group"
  port     = "3000" //changed from 8080 to 3000
  protocol = "HTTP"
  vpc_id   = "${aws_vpc.User_VPC.id}"
  tags = {
    name = "LoadBalancer-target-group"
  }
  health_check {
    healthy_threshold   = 3
    unhealthy_threshold = 5
    timeout             = 5
    interval            = 30 //changed removed one line of port
    path                = "/healthstatus"
    matcher             = "200"
  }
}

#Autoscalling Policy
resource "aws_autoscaling_policy" "WebServerScaleUpPolicy" {
  name                   = "WebServerScaleUpPolicy"
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = "${aws_autoscaling_group.awsAutoscalingGroup.name}"
  cooldown               = 60
  scaling_adjustment     = 1
}

resource "aws_autoscaling_policy" "WebServerScaleDownPolicy" {
  name                   = "WebServerScaleDownPolicy"
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = "${aws_autoscaling_group.awsAutoscalingGroup.name}"
  cooldown               = 60
  scaling_adjustment     = -1
}

resource "aws_cloudwatch_metric_alarm" "CPUAlarmHigh" {
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  statistic           = "Average"
  period              = "60"
  evaluation_periods  = "2"
  threshold           = "5"
  alarm_name          = "CPUAlarmHigh"
  comparison_operator = "GreaterThanThreshold"
  dimensions = {
  AutoScalingGroupName = "${aws_autoscaling_group.awsAutoscalingGroup.name}"
  }
  alarm_description = "Scale-up if CPU > 5% for 2 minutes"
  alarm_actions     = ["${aws_autoscaling_policy.WebServerScaleUpPolicy.arn}"]
}

resource "aws_cloudwatch_metric_alarm" "CPUAlarmLow" {
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  statistic           = "Average"
  period              = "60"
  evaluation_periods  = "2"
  threshold           = "3"
  alarm_name          = "CPUAlarmLow"
  comparison_operator = "LessThanThreshold"
  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.awsAutoscalingGroup.name}"
  }
  alarm_description = "Scale-down if CPU < 3% for 2 minutes"
  alarm_actions     = ["${aws_autoscaling_policy.WebServerScaleDownPolicy.arn}"]
}


resource "aws_security_group" "loadbalancer_security_group" {
  name   = "loadbalancer_security_group"
  vpc_id = "${aws_vpc.User_VPC.id}"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  #   ingress {
  #   from_port   = 80
  #   to_port     = 80
  #   protocol    = "tcp"
  #   cidr_blocks = ["0.0.0.0/0"]
  # }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name        = "LoadBalancer Security Group"
    Environment = "${var.profile}"
  }
}

resource "aws_lb" "WebappLoadbalancer" {
  name               = "WebappLoadbalancer"
  internal           = false
  load_balancer_type = "application"
  security_groups    = ["${aws_security_group.loadbalancer_security_group.id}"]
  subnets            = ["${aws_subnet.User_VPC_Subnet[0].id}","${aws_subnet.User_VPC_Subnet[1].id}","${aws_subnet.User_VPC_Subnet[2].id}"]// can be array
  ip_address_type    = "ipv4"
  tags = {
    Environment = "${var.profile}"
    Name        = "WebappLoadbalancer"
  }
}

# resource "aws_lb_listener" "webapp_listener" {
#   load_balancer_arn = "${aws_lb.WebappLoadbalancer.arn}"
#   port              = "80"
#   protocol          = "HTTP"

#   default_action {
#     type             = "forward"
#     target_group_arn = "${aws_lb_target_group.LoadBalancer-target-group.arn}"
#   }
# }

resource "aws_iam_policy" "LamdaPolicyforGhaction" {
  name   = "ghAction_s3_policy_lambda"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "lambda:*"
        ],
        
      "Resource": "arn:aws:lambda:${var.profile}:${local.account_id}:function:${aws_lambda_function.sns_lambda_email.function_name}"
    }
  ]
}
EOF
}

resource "aws_iam_user_policy_attachment" "ghAction_lambda_policy_attach" {
  user       = "ghactions"
  policy_arn = "${aws_iam_policy.LamdaPolicyforGhaction.arn}"
}

resource "aws_sns_topic" "sns_topics" {
  name = "email_request"
}

resource "aws_sns_topic_policy" "sns_policy" {
  arn    = "${aws_sns_topic.sns_topics.arn}"
  policy = "${data.aws_iam_policy_document.sns-topic-policy.json}"
}

data "aws_iam_policy_document" "sns-topic-policy" {
  policy_id = "__default_policy_ID"

  statement {
    actions = [
      "SNS:Subscribe",
      "SNS:SetTopicAttributes",
      "SNS:RemovePermission",
      "SNS:Receive",
      "SNS:Publish",
      "SNS:ListSubscriptionsByTopic",
      "SNS:GetTopicAttributes",
      "SNS:DeleteTopic",
      "SNS:AddPermission",
    ]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceOwner"

      values = [
        "${local.account_id}",
      ]
    }

    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    resources = [
      "${aws_sns_topic.sns_topics.arn}",
    ]

    sid = "__default_statement_ID"
  }
}


resource "aws_iam_policy" "sns_iam_policy" {
  name   = "ec2_iam_policy"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "SNS:Publish"
      ],
      "Resource": "${aws_sns_topic.sns_topics.arn}"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "ec2_sns_policy_attachment" {
  policy_arn = "${aws_iam_policy.sns_iam_policy.arn}"
  role       = "${aws_iam_role.role.name}"
}
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "index.js"
  output_path = "lambdaFunction.zip"
}
resource "aws_lambda_function" "sns_lambda_email" {
  filename         = "lambdaFunction.zip"
  function_name    = "Email_Service"
  role             = "${aws_iam_role.iam_for_lambda.arn}"
  handler          = "index.handler"
  runtime          = "nodejs12.x"
  source_code_hash = "${data.archive_file.lambda_zip.output_base64sha256}"
  environment {
    variables = {
      timeToLive = "300"
    }
  }
}

resource "aws_sns_topic_subscription" "lambda" {
  topic_arn = "${aws_sns_topic.sns_topics.arn}"
  protocol  = "lambda"
  endpoint  = "${aws_lambda_function.sns_lambda_email.arn}"
}

resource "aws_lambda_permission" "with_sns" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.sns_lambda_email.function_name}"
  principal     = "sns.amazonaws.com"
  source_arn    = "${aws_sns_topic.sns_topics.arn}"
}

resource "aws_iam_policy" "lambda_policy" {
  name        = "lambda_policy"
  description = "Cloud watch policies"
  policy      = <<EOF
{
   "Version": "2012-10-17",
   "Statement": [
       {
           "Effect": "Allow",
           "Action": [
               "logs:CreateLogGroup",
               "logs:CreateLogStream",
               "logs:PutLogEvents"
           ],
           "Resource": "*"
       },
       {
         "Sid": "LambdaDynamoDBAccess",
         "Effect": "Allow",
         "Action": [
             "dynamodb:GetItem",
             "dynamodb:PutItem",
             "dynamodb:UpdateItem"
         ],
         "Resource": "arn:aws:dynamodb:${var.region}:${local.account_id}:table/csye6225"
       },
       {
         "Sid": "LambdaSESAccess",
         "Effect": "Allow",
         "Action": [
             "ses:VerifyEmailAddress",
             "ses:SendEmail",
             "ses:SendRawEmail"
         ],
         "Resource": "*"
       }
   ]
}
 EOF
}

resource "aws_iam_role" "iam_for_lambda" {
  name = "iam_for_lambda"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "lambda_role_policy_attach" {
  role       = "${aws_iam_role.iam_for_lambda.name}"
  policy_arn = "${aws_iam_policy.lambda_policy.arn}"
}

resource "aws_iam_role_policy_attachment" "AWSLambdaBasicExecutionRole" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = "${aws_iam_role.iam_for_lambda.name}"
}


resource "aws_iam_role_policy_attachment" "AmazonSESFullAccess" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSESFullAccess"
  role       = "${aws_iam_role.iam_for_lambda.name}"
}

resource "aws_iam_user_policy_attachment" "LambdaExecution-attachment" {
  user = "ghactions"
  policy_arn = "arn:aws:iam::aws:policy/AWSLambdaFullAccess"
}


//ssl terraform
resource "aws_lb_listener" "webapp_listener" {
  load_balancer_arn = "${aws_lb.WebappLoadbalancer.arn}"
  port              = "443"
  protocol          = "HTTPS"
  certificate_arn   = "${data.aws_acm_certificate.ssl_certificate.arn}"


  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.LoadBalancer-target-group.arn}"
  }
}

data "aws_acm_certificate" "ssl_certificate" {
  domain   = "${var.routeprofile}.${var.domainName}"
  statuses = ["ISSUED"]
}

