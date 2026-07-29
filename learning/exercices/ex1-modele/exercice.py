"""Exercice 1 — Le modele de donnees.

Lis enonce.md, puis remplace chaque marqueur A_REMPLACER / NotImplementedError.
Verifie avec :  python3 -m unittest discover -v
"""

from __future__ import annotations

from enum import Enum


class Severity(Enum):
    """Severite d'un finding, comparable et ponderee.

    Doit supporter :
        Severity.LOW < Severity.CRITICAL   -> True
        sorted([Severity.HIGH, Severity.LOW])
        Severity.CRITICAL.weight           -> 10
    """

    # TODO: remplacer par INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL
    A_REMPLACER = 0

    # TODO: propriete weight -> 10 / 5 / 3 / 1 / 0

    # TODO: rendre les severites comparables entre elles


class Status(Enum):
    """Resultat d'un check. Status.PASS.value doit valoir "PASS"."""

    # TODO: PASS, FAIL, WARNING, NOT_AVAILABLE
    A_REMPLACER = "A_REMPLACER"


class Resource:
    """TODO: transformer en dataclass.

    Champs : id (obligatoire), type="", region="", name="", tags={}
    Attention au piege du dictionnaire par defaut partage entre instances.
    """


class Finding:
    """TODO: transformer en dataclass.

    Champs : check_id, title, severity, status, resource (obligatoires),
             remediation="", details=""
    Plus une methode to_dict() serialisable par json.dumps.
    """


def posture_score(findings: list) -> float:
    """Score de posture entre 0.0 et 100.0, arrondi a une decimale.

    100 * somme(poids des PASS) / somme(poids des PASS et FAIL).
    Les autres statuts sont ignores. Liste vide ou denominateur nul -> 100.0.
    """
    raise NotImplementedError
