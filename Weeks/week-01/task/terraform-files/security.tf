resource "aws_security_group" "open_ssh_port" {
  name            = "open_ssh_port"
  description     = "Allow traffic to sensitive ports from the internet"
  vpc_id          = aws_vpc.auditor_vpc.id


  ingress {
    description     = "allow traffic from internet to port 22 (SSH)"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    cidr_blocks     = ["0.0.0.0/0"]
  }

  ingress {
    description     = "allow traffic from internet to port 80 (HTTP)"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    cidr_blocks     = ["0.0.0.0/0"]
  }

  ingress {
    description     = "allow traffic from internet to port 443 (HTTPS)"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    cidr_blocks     = ["0.0.0.0/0"]
  }

  ingress {
    description     = "allow traffic from internet to port 3389 (RDP)"
    from_port       = 3389
    to_port         = 3389
    protocol        = "tcp"
    cidr_blocks     = ["0.0.0.0/0"]
  }

  egress {
    description     = "allow all traffic to internet"
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }

  tags {
    Name            = "SSH, HTTP, HTTPS, and RDP"
  }
}


resource "aws_security_group" "open_sensitive_ports" {
  name            = "open_sensitive_ports"
  description     = "allow traffic from internet to sensitive ports"
  vpc_id          = aws_vpc.auditor_vpc.id


  ingress {
    description     = "allow traffic from internet to port 3306 (MySQL)"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    cidr_blocks     = ["0.0.0.0/0"]
  }

  ingress {
    description     = "allow traffic from internet to port 5432 (PostgreSQL)"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    cidr_blocks     = ["0.0.0.0/0"]
  }

  ingress {
    description     = "allow traffic from internet to port 6379 (Redis)"
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    cidr_blocks     = ["0.0.0.0/0"]
  }

  ingress {
    description     = "allow traffic from internet to port 9200 (Elasticsearch)"
    from_port       = 9200
    to_port         = 9200
    protocol        = "tcp"
    cidr_blocks     = ["0.0.0.0/0"]
  }

  ingress {
    description     = "allow traffic from internet to port 27017 (MongoDB)"
    from_port       = 27017
    to-port         = 27017
    protocol        = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  egress {
    description     = "allow all traffic to the internet"
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }

  tags  {
    Name            = "MySQL, PostgreSQL, Redis, Elasticsearch, and MongoDB"
  }
}

