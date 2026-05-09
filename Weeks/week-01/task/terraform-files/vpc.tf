terraform {
	required_providers {
		aws       = {
			source  = "hashicorp/aws"
			version = "~> 6.0"
		}
	}
}


provider "aws" {
	region = "us-east-1"
}


resource "aws_vpc" "auditor_vpc" {
	cidr_block  = "10.0.0.0/16"

	tags = {
		Name      = "network_auditor_vpc"
	}
}


resource "aws_internet_gateway" "auditor_igw" {
	vpc_id = aws_vpc.auditor_vpc.id

	tags = {
		Name = "auditor_igw"
	}
}
		

resource "aws_subnet" "public_subnet" {
	vpc_id            = "aws_vpc.auditor_vpc.id"
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"

  tags              = {
    Name            = "public_subnet"
  }
}


resource "aws_subnet" "private_subnet" {
  vpc_id            = "aws_vpc.auditor_vpc.id"
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1b"

  tags              = {
    Name            = "private_subnet"
  }
}


resource "aws_route_table" "public_rt" {
  vpc_id            = "aws_vpc.auditor_vpc.id"

  route             = {
    cidr_block      = "0.0.0.0/0"
    gateway_id      = "aws_internet_gateway.auditor_igw.id"
  }

  tags              = {
    Name            = "public_rt"
  }
}


resource "aws_route_table_association" "public" {
  subnet_id         = "aws_subnet.public_subnet.id"
  route_table_id    = "aws_route_table.public_rt.id"
}


resource "aws-route_table" "private_rt" {
  vpc_id            = "aws_vpc.auditor_vpc.id"

  tags              = {
    Name            = "private_rt"
  }
}


resource "aws_route_table_association" "priavte" {
  subnet_id         = "aws_subnet.private_subnet.id"
  route_table_id    = "aws_route_table.private_rt.id"
}