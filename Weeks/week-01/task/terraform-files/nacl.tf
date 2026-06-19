resource "aws_default_network_acl" "network_auditor_default_nacl" {
  default_network_acl_id = aws_vpc.network_auditor_vpc.default_network_acl_id


  # Bad rule — low number, evaluated before everything else
  ingress {
    rule_no    = 50
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 23
    to_port    = 23
  }

  # Already-existing AWS default: allow all inbound
  ingress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  # Bad rule: SSH explicitly open
  ingress {
    rule_no    = 110
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 22
    to_port    = 22
  }

  # Bad rule: RDP explicitly open
  ingress {
    rule_no    = 120
    protocol   = "tcp"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 3389
    to_port    = 3389
  }

  # Already-existing AWS default: allow all outbound
  egress {
    rule_no    = 100
    protocol   = "-1"
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }
}