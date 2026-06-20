import boto3
import json
from dataclasses import dataclass
from typing import List

# Not an exhaustive list — Rhino Security Labs has documented ~20+ known IAM
# privilege-escalation paths. This covers the most common, high-signal ones.
# Worth expanding later as you encounter more in the wild.
PRIVILEGE_ESCALATION_ACTIONS = {
    'iam:passrole',
    'iam:createpolicyversion',
    'iam:setdefaultpolicyversion',
    'iam:attachuserpolicy',
    'iam:attachrolepolicy',
    'iam:attachgrouppolicy',
    'iam:putuserpolicy',
    'iam:putrolepolicy',
    'iam:putgrouppolicy',
    'iam:createaccesskey',
    'iam:updateassumerolepolicy',
    'sts:assumerole',
}

ADMIN_MANAGED_POLICY_ARNS = {
    'arn:aws:iam::aws:policy/AdministratorAccess',
}


@dataclass
class IAMFinding:
    role_name: str
    policy_name: str
    policy_type: str  # 'inline', 'managed', or 'trust'
    severity: str
    description: str


def check_iam_roles(region: str) -> List[IAMFinding]:
    """
    Scan all IAM roles for overly permissive policies and risky trust relationships.

    NOTE: IAM is a global service, not regional like EC2/VPC. The `region`
    parameter only affects which API endpoint boto3 calls — it does not
    filter or scope the data returned. Kept as a parameter purely so this
    function's call signature matches the other checkers in auditor.py.
    """
    iam = boto3.client('iam', region_name=region)
    findings = []

    paginator = iam.get_paginator('list_roles')
    for page in paginator.paginate():
        for role in page['Roles']:
            findings.extend(_check_role(iam, role))

    return findings


def _check_role(iam, role: dict) -> List[IAMFinding]:
    findings = []
    role_name = role['RoleName']

    # AWS service-linked roles are managed by AWS itself and can't be edited —
    # flagging them creates noise you have no ability to act on.
    if role.get('Path', '').startswith('/aws-service-role/'):
        return findings

    findings.extend(_check_trust_policy(role_name, role.get('AssumeRolePolicyDocument', {})))
    findings.extend(_check_managed_policies(iam, role_name))
    findings.extend(_check_inline_policies(iam, role_name))

    return findings


def _check_trust_policy(role_name: str, trust_doc: dict) -> List[IAMFinding]:
    """Who can assume this role — arguably more important than what the role can do."""
    findings = []
    statements = trust_doc.get('Statement', [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if stmt.get('Effect') != 'Allow':
            continue

        principal = stmt.get('Principal', {})

        # Wildcard principal — ANY AWS account/identity can assume this role
        if principal == '*' or principal.get('AWS') == '*':
            findings.append(IAMFinding(
                role_name=role_name, policy_name='AssumeRolePolicyDocument',
                policy_type='trust', severity='CRITICAL',
                description=f"Role '{role_name}' trust policy allows ANY AWS principal ('*') "
                             f"to assume it — effectively public, with no restriction on who "
                             f"can use it."
            ))
            continue

        # Cross-account trust without ExternalId — vulnerable to the
        # "confused deputy" problem if the trusted account ID becomes known
        aws_principal = principal.get('AWS')
        if aws_principal and 'sts:ExternalId' not in json.dumps(stmt.get('Condition', {})):
            findings.append(IAMFinding(
                role_name=role_name, policy_name='AssumeRolePolicyDocument',
                policy_type='trust', severity='MEDIUM',
                description=f"Role '{role_name}' allows cross-account assumption from "
                             f"{aws_principal} without an sts:ExternalId condition — "
                             f"vulnerable to confused-deputy risk if that account ID leaks."
            ))

    return findings


def _check_managed_policies(iam, role_name: str) -> List[IAMFinding]:
    findings = []
    attached = iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']

    for policy in attached:
        policy_arn = policy['PolicyArn']

        if policy_arn in ADMIN_MANAGED_POLICY_ARNS:
            findings.append(IAMFinding(
                role_name=role_name, policy_name=policy['PolicyName'],
                policy_type='managed', severity='CRITICAL',
                description=f"Role '{role_name}' has the AWS-managed 'AdministratorAccess' "
                             f"policy attached — full, unrestricted access to every AWS service."
            ))
            continue

        try:
            version_id = iam.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
            doc = iam.get_policy_version(
                PolicyArn=policy_arn, VersionId=version_id
            )['PolicyVersion']['Document']
        except Exception:
            continue  # skip unreadable/deprecated policies rather than crash the whole scan

        findings.extend(_check_policy_document(role_name, policy['PolicyName'], 'managed', doc))

    return findings


def _check_inline_policies(iam, role_name: str) -> List[IAMFinding]:
    findings = []
    inline_names = iam.list_role_policies(RoleName=role_name)['PolicyNames']

    for policy_name in inline_names:
        doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']
        findings.extend(_check_policy_document(role_name, policy_name, 'inline', doc))

    return findings


def _check_policy_document(role_name: str, policy_name: str, policy_type: str, doc: dict) -> List[IAMFinding]:
    findings = []
    statements = doc.get('Statement', [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if stmt.get('Effect') != 'Allow':
            continue

        actions = stmt.get('Action', [])
        if isinstance(actions, str):
            actions = [actions]
        actions_lower = [a.lower() for a in actions]

        resources = stmt.get('Resource', [])
        if isinstance(resources, str):
            resources = [resources]

        wildcard_action = '*' in actions
        wildcard_resource = '*' in resources

        # Full admin via wildcard action + wildcard resource — equivalent to AdministratorAccess
        if wildcard_action and wildcard_resource:
            findings.append(IAMFinding(
                role_name=role_name, policy_name=policy_name, policy_type=policy_type,
                severity='CRITICAL',
                description=f"Policy '{policy_name}' grants Action: '*' on Resource: '*' — "
                             f"equivalent to full administrator access, regardless of policy name."
            ))
            continue

        if wildcard_action:
            findings.append(IAMFinding(
                role_name=role_name, policy_name=policy_name, policy_type=policy_type,
                severity='HIGH',
                description=f"Policy '{policy_name}' grants Action: '*' (all actions) — "
                             f"even scoped to a specific resource, this is rarely intentional "
                             f"and should be replaced with explicit actions."
            ))
        elif wildcard_resource:
            shown = ', '.join(actions[:3]) + ('...' if len(actions) > 3 else '')
            findings.append(IAMFinding(
                role_name=role_name, policy_name=policy_name, policy_type=policy_type,
                severity='MEDIUM',
                description=f"Policy '{policy_name}' grants {shown} on Resource: '*' — "
                             f"access is not scoped to specific resources."
            ))

        # Privilege escalation primitives — dangerous regardless of resource scoping,
        # since these can be chained to grant broader access later
        matched_privesc = [a for a in actions_lower if a in PRIVILEGE_ESCALATION_ACTIONS]
        if matched_privesc:
            findings.append(IAMFinding(
                role_name=role_name, policy_name=policy_name, policy_type=policy_type,
                severity='HIGH',
                description=f"Policy '{policy_name}' grants {', '.join(matched_privesc)} — "
                             f"known privilege-escalation primitive(s). A principal with this "
                             f"permission can potentially grant itself broader access later."
            ))

    return findings