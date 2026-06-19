import boto3
from dataclasses import dataclass, field
from typing import List, Optional

DANGEROUS_PORTS = {
    22: ('SSH', 'CRITICAL'),
    3389: ('RDP', 'CRITICAL'),
    3306: ('MySQL', 'HIGH'),
    5432: ('PostgreSQL', 'HIGH'),
    1433: ('MSSQL', 'HIGH'),
    27017: ('MongoDB', 'HIGH'),
    6379: ('Redis', 'HIGH'),
    9200: ('Elasticsearch', 'HIGH'),
    443: ('HTTPS', 'INFO'),
    80: ('HTTP', 'LOW'),
}

@dataclass
class SGFinding:
    sg_id: str
    sg_name: str
    vpc_id: str
    port: int
    protocol: str
    cidr: str
    service: str
    severity: str
    description: str

def check_security_groups(region: str) -> List[SGFinding]:
    """Scan all security groups in a region for open ingress rules."""
    ec2 = boto3.client('ec2', region_name=region)
    paginator = ec2.get_paginator('describe_security_groups')
    
    findings = []
    
    for page in paginator.paginate():
        for sg in page['SecurityGroups']:
            findings.extend(_check_sg(sg))
    
    return findings

def _check_sg(sg: dict) -> List[SGFinding]:
    findings = []
    
    for rule in sg.get('IpPermissions', []):
        from_port = rule.get('FromPort', -1)
        to_port = rule.get('ToPort', -1)
        protocol = rule.get('IpProtocol', 'tcp')
        
        # Check IPv4 open CIDRs
        for ip_range in rule.get('IpRanges', []):
            if ip_range.get('CidrIp') in ('0.0.0.0/0',):
                finding = _create_finding(sg, from_port, to_port, protocol, ip_range['CidrIp'])
                if finding:
                    findings.append(finding)
        
        # Check IPv6 open CIDRs  
        for ip_range in rule.get('Ipv6Ranges', []):
            if ip_range.get('CidrIpv6') in ('::/0',):
                finding = _create_finding(sg, from_port, to_port, protocol, ip_range['CidrIpv6'])
                if finding:
                    findings.append(finding)
    
    return findings

def _create_finding(sg, from_port, to_port, protocol, cidr) -> Optional[SGFinding]:
    # All traffic rule
    if protocol == '-1':
        return SGFinding(
            sg_id=sg['GroupId'],
            sg_name=sg.get('GroupName', 'N/A'),
            vpc_id=sg.get('VpcId', 'N/A'),
            port=-1,
            protocol='ALL',
            cidr=cidr,
            service='ALL TRAFFIC',
            severity='CRITICAL',
            description=f"Security group allows ALL inbound traffic from {cidr}"
        )
    
    # Specific port checks
    if from_port in DANGEROUS_PORTS:
        service, severity = DANGEROUS_PORTS[from_port]
        return SGFinding(
            sg_id=sg['GroupId'],
            sg_name=sg.get('GroupName', 'N/A'),
            vpc_id=sg.get('VpcId', 'N/A'),
            port=from_port,
            protocol=protocol,
            cidr=cidr,
            service=service,
            severity=severity,
            description=f"Port {from_port} ({service}) open to the internet from {cidr}"
        )
    
    return None