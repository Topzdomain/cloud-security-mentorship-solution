terraform {
	required_providers {
		aws = {
			source = "hashicorp/aws"
			version "~> 6.0"
		}
	}
}

provider "aws" {
	region = "us-east-1"
}


resource "aws_vpc" "auditor_vpc" {
	cidr_block = "10.0.0.0/16"

	tags = {
		Name = "network_auditor_vpc"
	}
}



resource "aws_internet_gateway" "auditor_igw" {
	vpc_id = aws_vpc.auditor_vpc.id

	tags = {
		Name = "auditor_igw"
	}
}
		

resources "aws_subnet" "public_subnet" {
	vpc_id = "aws_vpc.auditor_vpc.id"

