The task for week 1 includes creating a VPC, Internet Gateway, Route Tables, Subnets, Security Group(s) and an AWS Network Security Auditor. All the infrastructure was deployed using Terraform.

In order for me to be able to carry out the task and project and also use Terraform to deploy the infrastructures, I carried out the following steps:


1. Logged into my AWS account manually and created a group named "Terraform-Course"
2. Gave some basic permissions to the group, such as EC2FullAccess, S3FULLACCESS, etc. I gave full access because I needed to carry out various tasks and didn't want to risk the code failing at any point.
3. Created a user named "Terraform-User" and added the user to the group.
4. Created access tokens/keys for the user.
5. I already have Terraform installed, so I just configured the AWS credentials in Terraform.

Next, I created and interconnected the VPC, internet gateway, route tables and subnets using Terraform scripts. I did not configure/enable flowlog for the VPC.
Using another Terraform script, I created a security group with inbound rules that allowed traffic from the internet (0.0.0.0/0) to sensitive ports like 22 (SSH), 80 (HTTP), 443 (HTTPS), 3389 (RDP), 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis), 9200 (Elasticsearch) and 27017 (MongoDB).
Lastly, the Python scripts to the Network Security Auditor.