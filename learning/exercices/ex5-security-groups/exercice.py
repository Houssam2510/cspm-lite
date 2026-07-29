"""Exercice 5 — Security groups exposes sur Internet.

Lis enonce.md. Verifie avec :  python3 -m unittest discover -v
"""

from __future__ import annotations

from commun import Finding, Resource, Severity, Status  # noqa: F401

PORTS_SENSIBLES = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
}

PROTOCOLES_TCP = {"tcp", "6"}
TOUS_PROTOCOLES = "-1"


def is_world_open(cidr: str) -> bool:
    """True pour 0.0.0.0/0 et ::/0. Utilise le module ipaddress."""
    raise NotImplementedError


def is_overly_broad(cidr: str) -> bool:
    """True si le reseau contient strictement plus de 65536 adresses."""
    raise NotImplementedError


def permission_covers_port(perm: dict, port: int) -> bool:
    """Protocole -1 -> tous les ports. tcp/6 -> plage FromPort..ToPort. Sinon False."""
    raise NotImplementedError


def permission_world_open(perm: dict) -> bool:
    """True si une plage IPv4 ou IPv6 de la permission est ouverte au monde."""
    raise NotImplementedError


def open_sensitive_ports(sg: dict) -> set[int]:
    """Ports de PORTS_SENSIBLES joignables depuis Internet."""
    raise NotImplementedError


def check_security_groups(sgs: list) -> list:
    """Un Finding NET-001 par security group. Voir le tableau de l'enonce."""
    raise NotImplementedError
