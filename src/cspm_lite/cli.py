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
from cspm_lite.config import Config, ConfigError, apply_exclusions, find_config, load_config
from cspm_lite.engine.models import ScanResult, Severity, Status
from cspm_lite.engine.registry import CheckMeta, get_checks, load_all_checks, run_checks
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
    scan.add_argument("--severity-min", help="severite minimale des controles executes")
    scan.add_argument(
        "--format", default="markdown", choices=sorted(RENDERERS), help="format de sortie"
    )
    scan.add_argument("-o", "--output", help="fichier de sortie (stdout par defaut)")
    scan.add_argument(
        "--fail-on", help="severite a partir de laquelle sortir en code 1 (NONE pour desactiver)"
    )
    scan.add_argument("--config", help="fichier de configuration (defaut : .cspm.toml remontant)")
    scan.add_argument("--no-config", action="store_true", help="ignorer tout fichier de config")
    scan.add_argument("--save-to", help="base SQLite ou historiser le scan")
    scan.add_argument(
        "--demo",
        action="store_true",
        help="utiliser un inventaire de demonstration, sans aucun appel AWS",
    )
    scan.add_argument("--max-workers", type=int, default=12, help="parallelisme de la collecte")

    liste = sous.add_parser("list-checks", help="lister les controles disponibles")
    liste.add_argument("--service", help="filtrer par service")
    liste.add_argument("--format", default="table", choices=("table", "json", "markdown"))

    histo = sous.add_parser("history", help="tendance de posture et metriques")
    histo.add_argument("--db", required=True, help="base SQLite produite par scan --save-to")
    histo.add_argument("--limit", type=int, default=50, help="nombre de scans a considerer")
    histo.add_argument("--format", default="markdown", choices=("markdown", "json", "html"))
    histo.add_argument("-o", "--output", help="fichier de sortie")
    histo.add_argument(
        "--seed-demo",
        action="store_true",
        help="remplir une base vide avec un historique simule, pour explorer la commande",
    )

    init = sous.add_parser("init-config", help="ecrire un .cspm.toml d'exemple")
    init.add_argument("-o", "--output", default=".cspm.toml")

    sous.add_parser("whoami", help="afficher l'identite AWS utilisee")
    return parser


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #


def _resoudre_config(args: argparse.Namespace) -> Config:
    """Fusionne fichier de configuration et arguments. Les arguments gagnent :
    la ligne de commande doit toujours pouvoir contredire le fichier."""
    config = Config()
    if not getattr(args, "no_config", False):
        chemin = Path(args.config) if getattr(args, "config", None) else find_config()
        if chemin is not None:
            if not chemin.is_file():
                raise ConfigError(f"fichier de configuration introuvable : {chemin}")
            config = load_config(chemin)
            log.info("configuration chargee depuis %s", chemin)

    if getattr(args, "severity_min", None):
        config.severity_min = args.severity_min
    if getattr(args, "fail_on", None):
        config.fail_on = args.fail_on
    if getattr(args, "service", None):
        config.services = [args.service]
    if getattr(args, "regions", None):
        config.regions = list(args.regions)
    return config


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
        print(
            f"{m.id:<{largeur_id}}  {m.severity.name:<{largeur_sev}}  {m.service:<11}  "
            f"{m.title}  {cis}"
        )
    print(f"\n{len(metas)} controles.")
    return EXIT_OK


def cmd_whoami(args: argparse.Namespace) -> int:
    from cspm_lite.auth import get_session, whoami

    identite = whoami(get_session(profile=getattr(args, "profile", None)))
    print(f"compte : {identite.account_id}")
    print(f"arn    : {identite.arn}")
    if identite.is_root:
        print(
            "\nAttention : vous utilisez le compte root. Utilisez un role dedie "
            "avec la policy SecurityAudit.",
            file=sys.stderr,
        )
    return EXIT_OK


def cmd_init_config(args: argparse.Namespace) -> int:
    from cspm_lite.config import EXEMPLE

    chemin = Path(args.output)
    if chemin.exists():
        print(f"{chemin} existe deja, rien n'a ete ecrit", file=sys.stderr)
        return EXIT_ERREUR
    chemin.parent.mkdir(parents=True, exist_ok=True)
    chemin.write_text(EXEMPLE, encoding="utf-8")
    print(f"configuration d'exemple ecrite dans {chemin}", file=sys.stderr)
    return EXIT_OK


def _checks_selectionnes(config: Config, args: argparse.Namespace) -> list[CheckMeta]:
    return get_checks(
        service=config.services[0] if config.services else None,
        severity_min=Severity.from_name(config.severity_min),
        ids=getattr(args, "checks", None),
    )


def _scan_demo(config: Config, args: argparse.Namespace) -> ScanResult:
    from cspm_lite.demo import build_demo_inventory

    inv = build_demo_inventory()
    debut = datetime.now(UTC)
    findings = run_checks(inv, _checks_selectionnes(config, args))
    return ScanResult(
        account_id=inv.account_id,
        findings=findings,
        regions=inv.regions,
        started_at=debut,
        finished_at=datetime.now(UTC),
        errors=list(inv.errors),
    )


def _scan_aws(config: Config, args: argparse.Namespace) -> ScanResult:
    # Importer les collecteurs peuple leur registre, comme pour les checks.
    import cspm_lite.collectors.scan_cloudtrail
    import cspm_lite.collectors.scan_ec2
    import cspm_lite.collectors.scan_iam
    import cspm_lite.collectors.scan_s3  # noqa: F401
    from cspm_lite.auth import get_session, list_regions, whoami
    from cspm_lite.collectors import collect_all
    from cspm_lite.engine.models import Inventory

    debut = datetime.now(UTC)
    session = get_session(
        profile=args.profile,
        role_arn=args.role_arn,
        external_id=args.external_id,
        region=config.regions[0] if config.regions else None,
    )
    identite = whoami(session)
    log.info("compte %s (%s)", identite.account_id, identite.arn)

    regions = config.regions or list_regions(session)
    log.info("%d region(s) a scanner", len(regions))

    inv = Inventory(account_id=identite.account_id, regions=regions, scanned_at=debut)
    collect_all(session, regions, inv, max_workers=args.max_workers)
    log.info("%d ressources collectees", inv.count)

    findings = run_checks(inv, _checks_selectionnes(config, args))
    return ScanResult(
        account_id=identite.account_id,
        findings=findings,
        regions=regions,
        started_at=debut,
        finished_at=datetime.now(UTC),
        errors=list(inv.errors),
    )


def cmd_scan(args: argparse.Namespace) -> int:
    load_all_checks()
    config = _resoudre_config(args)
    result = _scan_demo(config, args) if args.demo else _scan_aws(config, args)

    avertissements = apply_exclusions(result.findings, config)
    result.errors.extend(avertissements)
    for message in avertissements:
        log.warning("%s", message)

    if args.save_to:
        from cspm_lite.history import save_scan

        scan_id = save_scan(args.save_to, result)
        print(f"scan #{scan_id} enregistre dans {args.save_to}", file=sys.stderr)

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

    return _code_de_sortie(result, config.fail_on)


def cmd_history(args: argparse.Namespace) -> int:
    from cspm_lite.history import compute_metrics, diff_scans, list_scans
    from cspm_lite.reporters.history_reporter import render_history_html, render_history_markdown

    if getattr(args, "seed_demo", False) and not list_scans(args.db, limit=1):
        from cspm_lite.demo import seed_demo_history

        ecrits = seed_demo_history(args.db)
        print(f"{ecrits} scans de demonstration ecrits dans {args.db}", file=sys.stderr)

    if not Path(args.db).is_file():
        print(
            f"base introuvable : {args.db}\nlancez d'abord : cspm-lite scan --save-to " + args.db,
            file=sys.stderr,
        )
        return EXIT_ERREUR

    scans = list_scans(args.db, limit=args.limit)
    from cspm_lite.history import Diff

    diff = diff_scans(args.db, scans[-2].id, scans[-1].id) if len(scans) >= 2 else Diff()
    metrics = compute_metrics(args.db)

    if args.format == "json":
        sortie = json.dumps(
            {
                "scans": [
                    {
                        "id": s.id,
                        "started_at": s.started_at.isoformat(),
                        "score": s.score,
                        "pass": s.pass_count,
                        "fail": s.fail_count,
                    }
                    for s in scans
                ],
                "diff": {
                    "nouveaux": diff.nouveaux,
                    "resolus": diff.resolus,
                    "persistants": len(diff.persistants),
                },
                "metrics": {
                    "mttr_global_jours": metrics.mttr_global,
                    "mttr_par_severite": metrics.mttr_par_severite,
                    "corriges": metrics.corriges,
                    "ouverts": metrics.ouverts,
                    "taux_de_recidive": metrics.taux_de_recidive,
                },
            },
            indent=2,
            ensure_ascii=False,
        )
    elif args.format == "html":
        sortie = render_history_html(scans, diff, metrics)
    else:
        sortie = render_history_markdown(scans, diff, metrics)

    if args.output:
        chemin = Path(args.output)
        chemin.parent.mkdir(parents=True, exist_ok=True)
        chemin.write_text(sortie, encoding="utf-8")
        print(f"historique ecrit dans {chemin}", file=sys.stderr)
    else:
        print(sortie)
    return EXIT_OK


def _code_de_sortie(result: ScanResult, fail_on: str) -> int:
    """Traduit le resultat en code de sortie pour une CI."""
    if fail_on.upper() == "NONE":
        return EXIT_OK
    seuil = Severity.from_name(fail_on)
    declencheurs = [
        f
        for f in result.findings
        if f.status is Status.FAIL and not f.suppressed and not (f.severity < seuil)
    ]
    if declencheurs:
        print(f"{len(declencheurs)} finding(s) de severite >= {seuil.name}", file=sys.stderr)
        return EXIT_FINDINGS
    return EXIT_OK


COMMANDES = {
    "scan": cmd_scan,
    "list-checks": cmd_list_checks,
    "whoami": cmd_whoami,
    "history": cmd_history,
    "init-config": cmd_init_config,
}


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
    except Exception as exc:
        if args.verbose:
            raise
        print(f"erreur : {type(exc).__name__}: {exc}", file=sys.stderr)
        print("relancez avec -v pour la trace complete.", file=sys.stderr)
        return EXIT_ERREUR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
