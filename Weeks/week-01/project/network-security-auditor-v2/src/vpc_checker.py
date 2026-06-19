import boto3
from dataclasses import dataclass
from typing import List

@dataclass  
class VPCFinding:
    vpc_id: str
    vpc_name: str
    cidr: str
    severity: str
    issue: str
    description: str

def check_vpcs(region: str) -> List[VPCFinding]:
    ec2 = boto3.client('ec2', region_name=region)
    findings = []
    
    vpcs = ec2.describe_vpcs(Filters=[{'Name': 'state', 'Values': ['available']}])['Vpcs']
    
    for vpc in vpcs:
        vpc_id = vpc['VpcId']
        vpc_name = next((t['Value'] for t in vpc.get('Tags', []) if t['Key'] == 'Name'), 'Unnamed')
        
        # Check for flow logs
        flow_logs = ec2.describe_flow_logs(
            Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}]
        )['FlowLogs']
        
        if not flow_logs:
            findings.append(VPCFinding(
                vpc_id=vpc_id,
                vpc_name=vpc_name,
                cidr=vpc.get('CidrBlock', 'N/A'),
                severity='HIGH',
                issue='NO_FLOW_LOGS',
                description=f"VPC {vpc_id} has no VPC Flow Logs enabled — network traffic is unaudited"
            ))
        else:
            # Check if any flow log is in ACTIVE state
            active = [fl for fl in flow_logs if fl.get('FlowLogStatus') == 'ACTIVE']
            if not active:
                findings.append(VPCFinding(
                    vpc_id=vpc_id,
                    vpc_name=vpc_name,
                    cidr=vpc.get('CidrBlock', 'N/A'),
                    severity='HIGH',
                    issue='FLOW_LOGS_NOT_ACTIVE',
                    description=f"VPC {vpc_id} has flow logs configured but none are ACTIVE"
                ))
        
        # Check for default VPC usage
        if vpc.get('IsDefault'):
            findings.append(VPCFinding(
                vpc_id=vpc_id,
                vpc_name='DEFAULT',
                cidr=vpc.get('CidrBlock', 'N/A'),
                severity='MEDIUM',
                issue='DEFAULT_VPC_IN_USE',
                description="Default VPC detected — resources should use dedicated VPCs with custom network design"
            ))
    
    return findings