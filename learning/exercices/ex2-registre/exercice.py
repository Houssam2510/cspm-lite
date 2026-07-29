"""Exercice 2 — Le registre de checks et l'isolation des pannes.

Lis enonce.md. Verifie avec :  python3 -m unittest discover -v
"""

from __future__ import annotations

from commun import Finding, Resource, Severity, Status  # noqa: F401

# TODO: dataclass CheckMeta -> id, title, severity, service, func


REGISTRY: dict = {}


def check(*, id: str, title: str, severity, service: str):
    """Decorateur qui enregistre un check dans REGISTRY et renvoie la fonction telle quelle.

    Leve ValueError si l'id est deja enregistre.
    """
    raise NotImplementedError


def get_checks(service: str | None = None, severity_min=None) -> list:
    """Checks enregistres, dans l'ordre d'enregistrement, filtres.

    service      : insensible a la casse
    severity_min : garde les severites >= severity_min
    """
    raise NotImplementedError


def run_checks(inventory: dict, checks: list | None = None) -> list:
    """Execute les checks et concatene leurs findings.

    Un check qui leve une exception produit UN finding NOT_AVAILABLE dont `details`
    contient le message d'erreur, et l'execution continue.
    """
    raise NotImplementedError


def clear_registry() -> None:
    """Vide le registre (utilise par les tests)."""
    raise NotImplementedError
