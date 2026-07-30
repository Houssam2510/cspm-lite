"""Controles reseau et calcul (EC2, VPC).

Trois erreurs reviennent systematiquement dans les implementations naives de ces
controles, et sont traitees explicitement ici :

1. IPv6 oublie : `::/0` est aussi ouvert au monde que `0.0.0.0/0` ;
2. `IpProtocol: "-1"` (tous protocoles) n'a ni `FromPort` ni `ToPort` et ouvre tout ;
3. `FromPort`/`ToPort` decrivent une plage : 0-65535 couvre le port 22.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from cspm_lite.engine import resource_types as rt
from cspm_lite.engine.models import Finding, Inventory, Severity
from cspm_lite.engine.registry import check, make_finding

PORTS_SENSIBLES = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}

PROTOCOLES_TCP = {"tcp", "6"}
TOUS_PROTOCOLES = "-1"

# Un /16 (65 536 adresses) reste un perimetre d'entreprise plausible ; au-dela on
# considere la source trop large pour etre une restriction reelle.
SEUIL_PLAGE_LARGE = 65536


def is_world_open(cidr: str) -> bool:
    """True pour 0.0.0.0/0 et ::/0.

    On passe par `ipaddress` plutot que par une comparaison de chaines : "0.0.0.0/0"
    et "0.0.0.0/00" designent le meme reseau.
    """
    try:
        reseau = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    return reseau.prefixlen == 0


def is_overly_broad(cidr: str) -> bool:
    """True si la source couvre plus de 65 536 adresses."""
    try:
        return ipaddress.ip_network(cidr, strict=False).num_addresses > SEUIL_PLAGE_LARGE
    except ValueError:
        return False


def permission_covers_port(perm: dict[str, Any], port: int) -> bool:
    proto = str(perm.get("IpProtocol", ""))
    if proto == TOUS_PROTOCOLES:
        return True
    if proto not in PROTOCOLES_TCP:
        return False
    debut, fin = perm.get("FromPort"), perm.get("ToPort")
    if debut is None or fin is None:
        return False
    return int(debut) <= port <= int(fin)


def permission_sources(perm: dict[str, Any]) -> list[str]:
    """Sources IP de la permission. Les references a d'autres security groups
    (`UserIdGroupPairs`) sont volontairement exclues : ce n'est pas une exposition
    Internet, c'est meme la bonne pratique."""
    sources = [r["CidrIp"] for r in perm.get("IpRanges", []) if "CidrIp" in r]
    sources += [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", []) if "CidrIpv6" in r]
    return sources


def permission_world_open(perm: dict[str, Any]) -> bool:
    return any(is_world_open(c) for c in permission_sources(perm))


def open_sensitive_ports(raw: dict[str, Any]) -> set[int]:
    ouverts: set[int] = set()
    for perm in raw.get("IpPermissions", []):
        if not permission_world_open(perm):
            continue
        ouverts.update(p for p in PORTS_SENSIBLES if permission_covers_port(perm, p))
    return ouverts


def _format_ports(ports: set[int]) -> str:
    return ", ".join(f"{p} ({PORTS_SENSIBLES[p]})" for p in sorted(ports))


@check(
    id="NET-001",
    title="Port sensible expose sur Internet",
    severity=Severity.CRITICAL,
    service="ec2",
    cis="5.2",
    remediation="Restreindre la source a une plage connue. Pour l'administration, "
    "preferer AWS Systems Manager Session Manager, qui supprime le besoin d'ouvrir "
    "le port 22 ou 3389.",
)
def net_sensitive_ports(inv: Inventory) -> list[Finding]:
    findings = []
    for sg in inv.by_type(rt.EC2_SECURITY_GROUP):
        ports = open_sensitive_ports(sg.raw)
        findings.append(make_finding("NET-001", sg, not ports, _format_ports(ports)))
    return findings


@check(
    id="NET-002",
    title="Aucun security group n'ouvre tous les ports au monde",
    severity=Severity.CRITICAL,
    service="ec2",
    cis="5.2",
    remediation="Supprimer la regle 'tous protocoles' depuis 0.0.0.0/0 ou ::/0 et "
    "n'autoriser que les ports strictement necessaires.",
)
def net_all_ports_open(inv: Inventory) -> list[Finding]:
    findings = []
    for sg in inv.by_type(rt.EC2_SECURITY_GROUP):
        ouvert = any(
            str(perm.get("IpProtocol")) == TOUS_PROTOCOLES and permission_world_open(perm)
            for perm in sg.raw.get("IpPermissions", [])
        )
        findings.append(
            make_finding("NET-002", sg, not ouvert, "tous protocoles depuis 0.0.0.0/0" if ouvert else "")
        )
    return findings


@check(
    id="NET-003",
    title="Le security group par defaut n'autorise aucun trafic",
    severity=Severity.MEDIUM,
    service="ec2",
    cis="5.4",
    remediation="Vider les regles entrantes et sortantes du security group 'default' : "
    "il s'applique a toute ressource creee sans SG explicite.",
)
def net_default_sg_restricted(inv: Inventory) -> list[Finding]:
    findings = []
    for sg in inv.by_type(rt.EC2_SECURITY_GROUP):
        if sg.name != "default":
            continue
        entrantes = sg.raw.get("IpPermissions", [])
        sortantes = sg.raw.get("IpPermissionsEgress", [])
        details = []
        if entrantes:
            details.append(f"{len(entrantes)} regle(s) entrante(s)")
        if sortantes:
            details.append(f"{len(sortantes)} regle(s) sortante(s)")
        findings.append(make_finding("NET-003", sg, not details, ", ".join(details)))
    return findings


@check(
    id="NET-004",
    title="VPC Flow Logs actives",
    severity=Severity.MEDIUM,
    service="ec2",
    cis="3.7",
    remediation="Activer les Flow Logs sur chaque VPC : sans eux, une investigation "
    "post-incident n'a aucune trace reseau.",
)
def net_vpc_flow_logs(inv: Inventory) -> list[Finding]:
    findings = []
    for vpc in inv.by_type(rt.EC2_VPC):
        actif = bool(vpc.raw.get("flow_logs"))
        findings.append(make_finding("NET-004", vpc, actif, "" if actif else "aucun flow log"))
    return findings


@check(
    id="NET-005",
    title="Volumes EBS chiffres",
    severity=Severity.MEDIUM,
    service="ec2",
    cis="2.2.1",
    remediation="Activer le chiffrement par defaut des EBS au niveau de la region, puis "
    "recreer les volumes non chiffres a partir d'un instantane chiffre.",
)
def net_ebs_encrypted(inv: Inventory) -> list[Finding]:
    findings = []
    for volume in inv.by_type(rt.EC2_VOLUME):
        chiffre = bool(volume.raw.get("Encrypted"))
        findings.append(
            make_finding("NET-005", volume, chiffre, "" if chiffre else "volume non chiffre")
        )
    return findings


@check(
    id="NET-006",
    title="IMDSv2 obligatoire sur les instances EC2",
    severity=Severity.HIGH,
    service="ec2",
    cis="5.6",
    remediation="Passer HttpTokens a 'required' : IMDSv1 permet a une simple SSRF de "
    "lire les credentials du role d'instance. C'est le mecanisme de la breche "
    "Capital One de 2019.",
    references=(
        "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
    ),
)
def net_imdsv2_required(inv: Inventory) -> list[Finding]:
    findings = []
    for instance in inv.by_type(rt.EC2_INSTANCE):
        options = instance.raw.get("MetadataOptions") or {}
        tokens = options.get("HttpTokens", "optional")
        findings.append(
            make_finding("NET-006", instance, tokens == "required", f"HttpTokens = {tokens}")
        )
    return findings
