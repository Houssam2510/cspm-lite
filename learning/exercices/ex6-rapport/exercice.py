"""Exercice 6 — Agregation et rapport Markdown.

Lis enonce.md. Verifie avec :  python3 -m unittest discover -v
"""

from __future__ import annotations

from commun import Finding, Resource, Severity, Status  # noqa: F401


def summarize(findings: list) -> dict:
    """Resume chiffre : total, pass, fail, by_severity, score, pass_rate."""
    raise NotImplementedError


def top_offenders(findings: list, n: int = 3) -> list:
    """(resource.id, nb de FAIL), tries par nombre decroissant puis id croissant."""
    raise NotImplementedError


def render_markdown(findings: list) -> str:
    """Rapport Markdown. Respecte le gabarit exact de l'enonce."""
    raise NotImplementedError
