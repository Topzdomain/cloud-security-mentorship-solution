import boto3
from dataclasses import dataclass
from typing import List, Optional

# NOTE: This dict is duplicated from sg_checker.py for now. Worth refactoring
# both checkers to import from a shared src/constants.py once you have more
# than two checkers reusing it — duplication like this is a maintenance trap.
DANGEROUS_PORTS = {
    22: ('SSH', 'CRITICAL'),
    3389: ('RDP', 'CRITICAL'),
    3306: ('MySQL', 'HIGH'),
    5432: ('PostgreSQL', 'HIGH'),
    1433: ('MSSQL', 'HIGH'),
    27017: ('MongoDB', 'HIGH'),
    6379: ('Redis', 'HIGH'),
    9200: ('Elasticsearch', 'HIGH'),
    443: ('HTTPS', 'MEDIUM'),
    80: ('HTTP', 'MEDIUM'),
}

PROTOCOL_NAMES = {
    '-1': 'ALL',
    '6': 'TCP',
    '17': 'UDP',
    '1': 'ICMP',
}

OPEN_CIDRS = ('0.0.0.0/0', '::/0')

# AWS's implicit final deny-all rule present on every NACL — not a misconfiguration.
IMPLICIT_DENY_RULE_NUMBER = 32767

# Rules numbered at or below this are unusual — AWS's own default starts at 100,
# so anything lower was deliberately placed to be evaluated first.
LOW_RULE_NUMBER_THRESHOLD = 99

# Port ranges wider than this (port count) on INGRESS are treated as suspicious.
# Wide ranges on EGRESS are excluded because ephemeral return-traffic ports
# (1024-65535) are a legitimate, common pattern for stateless NACLs.
WIDE_PORT_RANGE_THRESHOLD = 100

EPHEMERAL_PORT_RANGE = (1024, 65535)


@dataclass
class NACLFinding:
    nacl_id: str
    vpc_id: str
    is_default: bool
    rule_number: int
    egress: bool
    protocol: str
    cidr: str
    port_range: str
    action: str
    severity: str
    description: str


def check_network_acls(region: str) -> List[NACLFinding]:
    """Scan all Network ACLs in a region for permissive or risky rules."""
    ec2 = boto3.client('ec2', region_name=region)
    paginator = ec2.get_paginator('describe_network_acls')

    findings = []

    for page in paginator.paginate():
        for nacl in page['NetworkAcls']:
            findings.extend(_check_nacl(nacl))

    return findings


def _check_nacl(nacl: dict) -> List[NACLFinding]:
    findings = []
    is_default = nacl.get('IsDefault', False)

    for entry in nacl.get('Entries', []):
        if entry.get('RuleNumber') == IMPLICIT_DENY_RULE_NUMBER:
            continue
        findings.extend(_check_entry(nacl, entry, is_default))

    findings.extend(_check_stateless_return_traffic(nacl, is_default))

    return findings


def _check_entry(nacl: dict, entry: dict, is_default: bool) -> List[NACLFinding]:
    findings = []

    rule_no = entry.get('RuleNumber', -1)
    egress = entry.get('Egress', False)
    action = entry.get('RuleAction', 'deny')
    protocol = entry.get('Protocol', '-1')
    cidr = entry.get('CidrBlock') or entry.get('Ipv6CidrBlock')
    direction = 'outbound' if egress else 'inbound'

    if action != 'allow' or cidr is None:
        return findings

    is_open = cidr in OPEN_CIDRS
    protocol_name = PROTOCOL_NAMES.get(protocol, protocol)

    port_range = entry.get('PortRange', {})
    from_port = port_range.get('From', -1)
    to_port = port_range.get('To', -1)
    port_label = 'ALL' if protocol == '-1' else f"{from_port}-{to_port}"

    # ── Check 1: allow-all rule (any protocol, any port) ───────────────────
    # NOTE: Severity is INFO, not CRITICAL. An allow-all NACL doesn't grant
    # access by itself — Security Groups are the actual access-control gate
    # and still must permit the traffic. This finding just flags the absence
    # of defense-in-depth at the network layer, which is normal in most
    # real-world environments that rely on SGs as the primary control.
    if is_open and protocol == '-1':
        default_note = " This is AWS's unmodified default rule — normal in most environments " \
                        "that rely on Security Groups as the primary access control." \
                        if (is_default and rule_no == 100) else ""
        findings.append(NACLFinding(
            nacl_id=nacl['NetworkAclId'], vpc_id=nacl.get('VpcId', 'N/A'),
            is_default=is_default, rule_number=rule_no, egress=egress,
            protocol='ALL', cidr=cidr, port_range='ALL', action=action,
            severity='INFO',
            description=f"Rule #{rule_no} allows ALL {direction} traffic from {cidr} — "
                         f"no network-layer restriction in place.{default_note}"
        ))

    # ── Check 2: specific dangerous port exposed ────────────────────────────
    elif is_open and protocol_name in ('TCP', 'UDP') and from_port == to_port and from_port in DANGEROUS_PORTS:
        service, severity = DANGEROUS_PORTS[from_port]
        findings.append(NACLFinding(
            nacl_id=nacl['NetworkAclId'], vpc_id=nacl.get('VpcId', 'N/A'),
            is_default=is_default, rule_number=rule_no, egress=egress,
            protocol=protocol_name, cidr=cidr, port_range=port_label, action=action,
            severity=severity,
            description=f"Rule #{rule_no} allows {direction} {service} (port {from_port}) from {cidr}"
        ))

    # ── Check 3: wide port range on ingress only ────────────────────────────
    elif (not egress and is_open and protocol_name in ('TCP', 'UDP')
          and from_port != -1 and (to_port - from_port + 1) > WIDE_PORT_RANGE_THRESHOLD):
        findings.append(NACLFinding(
            nacl_id=nacl['NetworkAclId'], vpc_id=nacl.get('VpcId', 'N/A'),
            is_default=is_default, rule_number=rule_no, egress=egress,
            protocol=protocol_name, cidr=cidr, port_range=port_label, action=action,
            severity='HIGH',
            description=f"Rule #{rule_no} allows a wide inbound port range ({port_label}) "
                         f"from {cidr} — likely a lazy rule rather than a deliberate need"
        ))

    # ── Check 4: ICMP open to the internet ──────────────────────────────────
    elif is_open and protocol_name == 'ICMP':
        findings.append(NACLFinding(
            nacl_id=nacl['NetworkAclId'], vpc_id=nacl.get('VpcId', 'N/A'),
            is_default=is_default, rule_number=rule_no, egress=egress,
            protocol='ICMP', cidr=cidr, port_range='N/A', action=action,
            severity='MEDIUM',
            description=f"Rule #{rule_no} allows ICMP {direction} from {cidr} — "
                         f"enables network reconnaissance (ping sweeps, traceroute mapping)"
        ))

    # ── Check 5: unusually low rule number ──────────────────────────────────
    if rule_no <= LOW_RULE_NUMBER_THRESHOLD:
        findings.append(NACLFinding(
            nacl_id=nacl['NetworkAclId'], vpc_id=nacl.get('VpcId', 'N/A'),
            is_default=is_default, rule_number=rule_no, egress=egress,
            protocol=protocol_name, cidr=cidr, port_range=port_label, action=action,
            severity='MEDIUM',
            description=f"Rule #{rule_no} uses an unusually low rule number. AWS's own "
                         f"default rules start at 100 — a number this low suggests it was "
                         f"deliberately placed to be evaluated before other rules, "
                         f"which is worth a deliberate review of evaluation order."
        ))

    return findings


def _check_stateless_return_traffic(nacl: dict, is_default: bool) -> List[NACLFinding]:
    """
    NACLs are stateless — an inbound allow rule has no effect unless a matching
    outbound rule permits the response. This checks whether any restricted
    (non-wildcard) inbound allow rule exists without ephemeral ports (1024-65535)
    open on egress, which would silently drop return traffic.
    """
    entries = nacl.get('Entries', [])

    has_restricted_ingress_allow = any(
        e.get('RuleAction') == 'allow' and not e.get('Egress', False)
        and e.get('Protocol') != '-1'
        and (e.get('CidrBlock') or e.get('Ipv6CidrBlock'))
        for e in entries
    )

    def _covers_ephemeral(e):
        pr = e.get('PortRange', {})
        return (e.get('Protocol') == '-1' or
                (pr.get('From', 99999) <= EPHEMERAL_PORT_RANGE[0]
                 and pr.get('To', -1) >= EPHEMERAL_PORT_RANGE[1]))

    has_ephemeral_egress = any(
        e.get('RuleAction') == 'allow' and e.get('Egress', False) and _covers_ephemeral(e)
        for e in entries
    )

    if has_restricted_ingress_allow and not has_ephemeral_egress:
        return [NACLFinding(
            nacl_id=nacl['NetworkAclId'], vpc_id=nacl.get('VpcId', 'N/A'),
            is_default=is_default, rule_number=-1, egress=True,
            protocol='N/A', cidr='N/A', port_range='1024-65535', action='N/A',
            severity='MEDIUM',
            description="No egress rule covers the ephemeral port range (1024-65535). "
                        "NACLs are stateless — without this, return traffic for restricted "
                        "inbound connections may be silently dropped."
        )]

    return []