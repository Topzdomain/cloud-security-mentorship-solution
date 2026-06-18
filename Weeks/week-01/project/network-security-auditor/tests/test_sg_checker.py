import pytest
from moto import mock_aws
import boto3
from src.sg_checker import check_security_groups

@mock_aws
def test_detects_open_ssh():
    ec2 = boto3.client('ec2', region_name='us-east-1')
    
    # Create VPC and SG with open SSH
    vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')['Vpc']
    sg = ec2.create_security_group(
        GroupName='test-open-ssh',
        Description='Test SG',
        VpcId=vpc['VpcId']
    )
    ec2.authorize_security_group_ingress(
        GroupId=sg['GroupId'],
        IpPermissions=[{
            'IpProtocol': 'tcp',
            'FromPort': 22,
            'ToPort': 22,
            'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
        }]
    )
    
    findings = check_security_groups('us-east-1')
    ssh_findings = [f for f in findings if f.port == 22 and f.severity == 'CRITICAL']
    assert len(ssh_findings) >= 1

@mock_aws
def test_no_findings_for_private_cidr():
    ec2 = boto3.client('ec2', region_name='us-east-1')
    vpc = ec2.create_vpc(CidrBlock='10.0.0.0/16')['Vpc']
    sg = ec2.create_security_group(
        GroupName='test-private',
        Description='Private SG',
        VpcId=vpc['VpcId']
    )
    ec2.authorize_security_group_ingress(
        GroupId=sg['GroupId'],
        IpPermissions=[{
            'IpProtocol': 'tcp',
            'FromPort': 22,
            'ToPort': 22,
            'IpRanges': [{'CidrIp': '10.0.0.0/8'}]
        }]
    )
    
    findings = check_security_groups('us-east-1')
    # Private CIDR SSH should not be flagged
    open_ssh = [f for f in findings if f.port == 22 and f.cidr == '10.0.0.0/8']
    assert len(open_ssh) == 0