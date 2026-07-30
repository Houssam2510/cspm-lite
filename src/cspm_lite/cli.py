"""Interface en ligne de commande.

Choix assume : `argparse` de la bibliotheque standard plutot que Typer ou Click.
Pour un outil de securite, chaque dependance est une surface d'attaque de la chaine
d'approvisionnement ; `cspm-lite list-checks` et `cspm-lite scan --demo` fonctionnent
donc sans installer quoi que ce soit. boto3 n'est importe que lorsqu'un vrai scan est
demande - c'est pour cela que les imports du module `scanner` sont differes.

Codes de sortie, qui constituent le contrat avec une CI :
    0  aucun finding au-dessus du seuil
    1  au moins un finding atteint ou depasse --fail-on
    2  erreur d'execution (credentials, droits, panne)
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

from cspm_lite import __version__
from cspm_lite.engine.models import ScanResult, Severity, Status
from cspm_lite.engine.registry import get_checks, load_all_checks, run_checks
from cspm_lite.reporters import RENDERERS

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERREUR = 2

log = logging.getLogger("cspm_lite")


# --------------------------------------------------------------------------- #
# Analyse des arguments
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cspm-lite",
        description="Scanner de posture de securite cloud (CSPM) pour AWS.",
        epilog="Auditez uniquement des comptes qui vous appartiennent ou pour lesquels "
        "vous disposez d'une autorisation ecrite.",
    )
    parser.add_argument("--version", action="version", version=f"cspm-lite {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="journalisation detaillee")
    sous = parser.add_subparsers(dest="commande", required=True)

    scan = sous.add_parser("scan", help="auditer un compte AWS")
    scan.add_argument("--profile", help="profil AWS CLI a utiliser")
    scan.add_argument("--role-arn", help="role a assumer (acces cross-compte)")
    scan.add_argument("--external-id", help="ExternalId associe au role")
    scan.add_argument(
        "--region",
        action="append",
        dest="regions",
        help="region a scanner (repetable ; toutes les regions activees par defaut)",
    )
    scan.add_argument("--service", help="limiter a un service (s3, iam, ec2, cloudtrail)")
    scan.add_argument("--check", action="append", dest="checks", help="limiter a des checks precis")
    scan.add_argument(
        "--severity-min",
        default="INFORMATIONAL",
        help="severite minimale des controles executes",
    )
    scan.add_argument(
        "--format", default="markdown", choices=sorted(RENDERERS), help="format de sortie"
    )
    scan.add_argument("-o", "--output", help="fichier de sortie (stdout par defaut)")
    scan.add_argument(
        "--fail-on",
        default="HIGH",
        help="severite a partir de laquelle sortir en code 1 (NONE pour desactiver)",
    )
    scan.add_argument(
        "--demo",
        action="store_true",
        help="utiliser un inventaire de demonstration, sans aucun appel AWS",
    )
    scan.add_argument("--max-workers", type=int, default=12, help="parallelisme de la collecte")

    liste = sous.add_parser("list-checks", help="lister les controles disponibles")
    liste.add_argument("--service", help="filtrer par service")
    liste.add_argument("--format", default="table", choices=("table", "json", "markdown"))

    sous.add_parser("whoami", help="afficher l'identite AWS utilisee")
    return parser


# --------------------------------------------------------------------------- #
# Commandes
# --------------------------------------------------------------------------- #


def cmd_list_checks(args: argparse.Namespace) -> int:
    load_all_checks()
    metas = get_checks(service=args.service)
    if not metas:
        print("aucun check ne correspond au filtre", file=sys.stderr)
        return EXIT_ERREUR

    if args.format == "json":
        print(
            json.dumps(
                [
                    {
                        "id": m.id,
                        "title": m.title,
                        "severity": m.severity.name,
                        "service": m.service,
                        "cis": m.cis,
                        "remediation": m.remediation,
                    }
                    for m in metas
                ],
                indent=2,
                ensure_ascii=False,
            )
        )
        return EXIT_OK

    if args.format == "markdown":
        print("| ID | Service | Severite | CIS | Titre |")
        print("| --- | --- | --- | --- | --- |")
        for m in metas:
            print(f"| {m.id} | {m.service} | {m.severity.name} | {m.cis or '—'} | {m.title} |")
        return EXIT_OK

    largeur_id = max(len(m.id) for m in metas)
    largeur_sev = max(len(m.severity.name) for m in metas)
    for m in metas:
        cis = f"CIS {m.cis}" if m.cis else ""
        print(f"{m.id:<{largeur_id}}  {m.severity.name:<{largeur_sev}}  {m.service:<11}  "
              f"{m.title}  {cis}")
    print(f"\n{len(metas)} controles.")
    return EXIT_OK


def cmd_whoami(args: argparse.Namespace) -> int:
    from cspm_lite.auth import get_session, whoami

    identite = whoami(get_session(profile=getattr(args, "profile", None)))
    print(f"compte : {identite.account_id}")
    print(f"arn    : {identite.arn}")
    if identite.is_root:
        print("\nAttention : vous utilisez le compte root. Utilisez un role dedie "
              "avec la policy SecurityAudit.", file=sys.stderr)
    return EXIT_OK


def _scan_demo(args: argparse.Namespace) -> ScanResult:
    from cspm_lite.demo import build_demo_inventory

    inv = build_demo_inventory()
    debut = datetime.now(UTC)
    findings = run_checks(inv, _checks_selectionnes(args))
    return ScanResult(
        account_id=inv.account_id,
        findings=findings,
        regions=inv.regions,
        started_at=debut,
        finished_at=datetime.now(UTC),
        errors=inv.errors,
    )


def _checks_selectionnes(args: argparse.Namespace) -> list:
    severity_min = Severity.from_name(args.severity_min)
    return get_checks(service=args.service, severity_min=severity_min, ids=args.checks)


def _scan_aws(args: argparse.Namespace) -> ScanResult:
    from cspm_lite.auth import get_session, list_regions, whoami
    from cspm_lite.collectors import collect_all
    from cspm_lite.engine.models import Inventory

    # Importer les collecteurs peuple leur registre, comme pour les checks.
    import cspm_lite.collectors.scan_cloudtrail  # noqa: F401
    import cspm_lite.collectors.scan_ec2  # noqa: F401
    import cspm_lite.collectors.scan_iam  # noqa: F401
    import cspm_lite.collectors.scan_s3  # noqa: F401

    debut = datetime.now(UTC)
    session = get_session(
        profile=args.profile,
        role_arn=args.role_arn,
        external_id=args.external_id,
        region=args.regions[0] if args.regions else None,
    )
    identite = whoami(session)
    log.info("compte %s (%s)", identite.account_id, identite.arn)

    regions = args.regions or list_regions(session)
    log.info("%d region(s) a scanner", len(regions))

    inv = Inventory(account_id=identite.account_id, regions=regions, scanned_at=debut)
    collect_all(session, regions, inv, max_workers=args.max_workers)
    log.info("%d ressources collectees", inv.count)

    findings = run_checks(inv, _checks_selectionnes(args))
    return ScanResult(
        account_id=identite.account_id,
        findings=findings,
        regions=regions,
        started_at=debut,
        finished_at=datetime.now(UTC),
        errors=inv.errors,
    )


def cmd_scan(args: argparse.Namespace) -> int:
    load_all_checks()
    result = _scan_demo(args) if args.demo else _scan_aws(args)

    sortie = RENDERERS[args.format](result)
    if args.output:
        chemin = Path(args.output)
        chemin.parent.mkdir(parents=True, exist_ok=True)
        chemin.write_text(sortie, encoding="utf-8")
        print(
            f"rapport ecrit dans {chemin} — score {result.score}/100, "
            f"{len(result.failed)} finding(s) en echec",
            file=sys.stderr,
        )
    else:
        print(sortie)

    return _code_de_sortie(result, args.fail_on)


def _code_de_sortie(result: ScanResult, fail_on: str) -> int:
    """Traduit le resultat en code de sortie pour une CI."""
    if fail_on.upper() == "NONE":
        return EXIT_OK
    seuil = Severity.from_name(fail_on)
    declencheurs = [
        f for f in result.findings if f.status is Status.FAIL and not (f.severity < seuil)
    ]
    if declencheurs:
        print(
            f"{len(declencheurs)} finding(s) de severite >= {seuil.name}",
            file=sys.stderr,
        )
        return EXIT_FINDINGS
    return EXIT_OK


COMMANDES = {"scan": cmd_scan, "list-checks": cmd_list_checks, "whoami": cmd_whoami}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    try:
        return COMMANDES[args.commande](args)
    except KeyboardInterrupt:
        print("interrompu", file=sys.stderr)
        return EXIT_ERREUR
    except Exception as exc:  # noqa: BLE001 - point de sortie unique de la CLI
        if args.verbose:
            raise
        print(f"erreur : {type(exc).__name__}: {exc}", file=sys.stderr)
        print("relancez avec -v pour la trace complete.", file=sys.stderr)
        return EXIT_ERREUR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
