"""Sortie Markdown : le format destine aux commentaires de pull request.

C'est ce qui fait qu'un outil de securite est lu par les developpeurs plutot
qu'ignore. La regle de conception : le rapport doit repondre a une seule question,
"qu'est-ce que je corrige en premier ?" - donc resume chiffre en tete, detail
groupe par severite decroissante, et remediation systematiquement affichee.
"""

from __future__ import annotations

from cspm_lite.engine.models import ScanResult, Severity


def _echapper(texte: str) -> str:
    """Neutralise les pipes, qui casseraient les tableaux Markdown."""
    return texte.replace("|", "\\|")


def render_markdown(result: ScanResult) -> str:
    lignes: list[str] = ["# Rapport de posture cspm-lite", ""]
    lignes.append(
        f"**Score : {result.score} / 100** — {len(result.passed)} controles conformes, "
        f"{len(result.failed)} en echec "
        f"(compte `{result.account_id or 'inconnu'}`, {len(result.regions)} region(s))"
    )
    lignes.append("")

    lignes += ["| Severite | Echecs |", "| --- | --- |"]
    for nom, nombre in result.counts_by_severity.items():
        lignes.append(f"| {nom} | {nombre} |")
    if not result.counts_by_severity:
        lignes.append("| — | 0 |")
    lignes.append("")

    if not result.failed:
        lignes.append("Aucun finding en echec.")
        return "\n".join(lignes) + "\n"

    lignes += ["## Findings en echec", ""]
    for severite in sorted(Severity, key=lambda s: s.weight, reverse=True):
        groupe = [f for f in result.failed if f.severity is severite]
        if not groupe:
            continue
        titre = f"<summary><b>{severite.name}</b> — {len(groupe)}</summary>"
        lignes += ["<details open>", titre, ""]
        for f in groupe:
            cis = f" · CIS {f.cis}" if f.cis else ""
            lignes.append(f"- **{f.check_id}**{cis} — {_echapper(f.title)} — `{f.resource.id}`")
            if f.details:
                lignes.append(f"  - constat : {_echapper(f.details)}")
            if f.remediation:
                lignes.append(f"  - remediation : {_echapper(f.remediation)}")
        lignes += ["", "</details>", ""]

    if result.errors:
        lignes += ["## Avertissements de collecte", ""]
        lignes += [f"- {_echapper(e)}" for e in result.errors]
        lignes.append("")

    return "\n".join(lignes)
