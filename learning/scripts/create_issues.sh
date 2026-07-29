#!/usr/bin/env bash
# Cree les labels et les 30 issues du backlog cspm-lite.
# Prerequis : gh (GitHub CLI) installe et authentifie (gh auth login).
# Usage : bash learning/scripts/create_issues.sh [--dry-run]

set -euo pipefail

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

if [[ $DRY_RUN -eq 0 ]]; then
  command -v gh >/dev/null || { echo "gh n'est pas installe : https://cli.github.com"; exit 1; }
  gh auth status >/dev/null 2>&1 || { echo "Lance d'abord : gh auth login"; exit 1; }
fi

run() {
  if [[ $DRY_RUN -eq 1 ]]; then printf '[dry-run] %s\n' "$*"; else "$@"; fi
}

# ---------- Labels ----------
create_label() {  # nom couleur description
  if [[ $DRY_RUN -eq 1 ]]; then printf '[dry-run] label %s\n' "$1"; return; fi
  gh label create "$1" --color "$2" --description "$3" --force >/dev/null 2>&1 \
    || echo "  label $1 : deja present ou non cree"
}

echo "== Creation des labels =="
create_label phase-0  ededed "Fondations du projet"
create_label phase-1  c5def5 "Modele de donnees et moteur"
create_label phase-2  c5def5 "Auth et collecteurs"
create_label phase-3  d93f0b "Checks de securite"
create_label phase-4  bfd4f2 "Reporters"
create_label phase-5  bfd4f2 "CLI"
create_label phase-6  0e8a16 "Labo Terraform"
create_label phase-7  fbca04 "Tests"
create_label phase-8  1d76db "CI/CD et Docker"
create_label phase-9  5319e7 "Volet data"
create_label phase-10 006b75 "Finition et valorisation"
create_label cloud    0052cc "AWS / infrastructure"
create_label security b60205 "Securite"
create_label data     5319e7 "Donnees et reporting"
create_label devops   1d76db "Outillage et CI"
create_label tests    fbca04 "Tests"
create_label docs     0075ca "Documentation"

# ---------- Issues ----------
new_issue() {  # titre labels corps
  echo "  -> $1"
  run gh issue create --title "$1" --label "$2" --body "$3"
}

echo "== Creation des issues =="

new_issue "Remplir pyproject.toml et rendre le paquet installable" "phase-0,devops" \
'Metadonnees PEP 621, dependances runtime (boto3, typer, rich, pydantic) et dev (pytest, pytest-cov, moto, ruff, mypy), layout src/, entry point `cspm-lite = cspm_lite.cli:app`.

**DoD** : `pip install -e ".[dev]"` fonctionne et `import cspm_lite` passe.'

new_issue "Configurer ruff et mypy en mode strict" "phase-0,devops" \
'Sections [tool.ruff] et [tool.mypy] dans pyproject.toml, mypy en mode strict.

**DoD** : `ruff check . && mypy src` sortent en 0.'

new_issue "README initial" "phase-0,docs" \
'Titre, pitch dune phrase, avertissement legal (usage sur ses propres comptes uniquement), installation, roadmap en 3 lignes.'

new_issue "engine/models.py : Severity, Status, Resource, Finding, ScanResult" "phase-1,data" \
'Enums alignes sur ASFF. Resource conserve la reponse brute dans `raw`. ScanResult expose counts_by_severity, pass_rate et score.

**DoD** : serialisation JSON aller-retour testee.'

new_issue "engine/registry.py : decorateur @check et registre" "phase-1" \
'`@check(id, title, severity, service, cis, remediation)` enregistre la fonction. `get_checks(services, severity_min)` filtre. `run_checks(inventory)` execute.

**DoD** : un check factice est decouvert et execute par le registre.'

new_issue "Isolation des pannes dans le moteur" "phase-1" \
'Un check qui leve une exception produit un Finding de statut NOT_AVAILABLE avec le message derreur, sans interrompre les autres checks.

**DoD** : un test avec un check qui raise prouve que le scan continue.'

new_issue "Scoring de posture" "phase-1,data" \
'Score pondere par severite (CRITICAL=10, HIGH=5, MEDIUM=3, LOW=1). Documenter la formule dans le README.'

new_issue "auth.py : sessions, profils, AssumeRole, STS" "phase-2,cloud,security" \
'`get_session(profile, role_arn, external_id, region)`, `whoami()`, `list_regions()`, retries adaptatifs via botocore.Config.

**DoD** : `cspm-lite whoami` affiche laccount id et lARN de lappelant.'

new_issue "Interface commune Collector" "phase-2" \
'Protocol avec name, service, collect(session) -> list[Resource].'

new_issue "collectors/scan_s3.py" "phase-2,cloud" \
'Buckets + location, public access block, ACL, policy, chiffrement, versioning, logging. Traiter NoSuchBucketPolicy et ServerSideEncryptionConfigurationNotFoundError comme des etats normaux.'

new_issue "collectors/scan_iam.py avec credential report" "phase-2,cloud,security" \
'Users, cles + get_access_key_last_used, MFA, policies attachees, password policy, et le credential report (API asynchrone -> CSV base64, avec attente et timeout).'

new_issue "collectors/scan_ec2.py multi-region et parallele" "phase-2,cloud" \
'SG, instances, volumes, VPC, flow logs sur toutes les regions actives via ThreadPoolExecutor. Justifier le choix threads vs processus dans le docstring.

**DoD** : scan complet de 17 regions en moins de 60 s.'

new_issue "collectors/scan_cloudtrail.py" "phase-2,cloud" \
'describe_trails, get_trail_status, get_event_selectors.'

new_issue "Gestion du throttling et des permissions manquantes" "phase-2,cloud" \
'AccessDenied sur un appel ne doit pas tuer le scan : le collector remonte un avertissement et continue. Documenter la policy IAM minimale requise (SecurityAudit).'

new_issue "s3_checks.py : 8 checks" "phase-3,security" \
'S3-001 Block Public Access, S3-002 ACL publique, S3-003 policy publique, S3-004 chiffrement, S3-005 versioning, S3-006 access logging, S3-007 TLS obligatoire, S3-008 MFA Delete.

Chaque check porte son ID CIS, son texte de remediation et un lien de reference.

**DoD** : 2 tests par check (un PASS, un FAIL).'

new_issue "iam_checks.py : 10 checks" "phase-3,security" \
'IAM-001 pas de cle root, IAM-002 MFA root, IAM-003 MFA utilisateurs console, IAM-004 cles > 90 jours, IAM-005 credentials inutilisees > 45 jours, IAM-006 password policy, IAM-007 pas dAdministratorAccess direct, IAM-008 pas de policy custom *:*, IAM-009 support role, IAM-010 une seule cle active.

Le check "cles > 90 jours" doit sappuyer sur le credential report.'

new_issue "net_checks.py : 9 checks" "phase-3,security" \
'NET-001 SSH ouvert, NET-002 RDP ouvert, NET-003 bases de donnees exposees, NET-004 tous ports ouverts, NET-005 SG default permissif, NET-006 VPC Flow Logs, NET-007 chiffrement EBS, NET-008 IP publiques, NET-009 IMDSv2 obligatoire.

Traiter les CIDR avec le module ipaddress (0.0.0.0/0 mais aussi ::/0 et les plages trop larges).'

new_issue "log_checks.py : 6 checks" "phase-3,security" \
'LOG-001 CloudTrail multi-region, LOG-002 validation dintegrite, LOG-003 bucket de logs non public, LOG-004 chiffrement KMS, LOG-005 integration CloudWatch, LOG-006 journalisation des acces au bucket. Mappes sur CIS section 3.'

new_issue "Catalogue des checks en Markdown genere" "phase-3,docs" \
'Une commande qui genere docs/CHECKS.md depuis le registre : id, titre, severite, CIS, remediation. La doc ne peut plus diverger du code.'

new_issue "json_reporter.py avec schema versionne" "phase-4,data" \
'Sortie machine, schema stable, champ schema_version.'

new_issue "markdown_reporter.py pour les commentaires de PR" "phase-4,data" \
'Resume chiffre en tete, puis detail groupe par severite, repliable via <details>.'

new_issue "html_reporter.py : rapport autonome" "phase-4,data" \
'Un seul fichier, CSS et JS inline, aucun CDN. Score, repartition par severite, tableau triable et filtrable. Lisible en mode sombre.'

new_issue "asff_reporter.py : integration AWS Security Hub" "phase-4,cloud,security" \
'Champs ASFF obligatoires, validation du format contre la doc AWS.'

new_issue "CLI Typer : scan, list-checks, version, whoami" "phase-5" \
'Options completes (--profile, --role-arn, --region, --service, --severity-min, --format, --output, --fail-on), barre de progression Rich, sortie coloree.'

new_issue "Fichier de configuration .cspm.yml et exclusions" "phase-5,security" \
'Exclusions avec champs obligatoires reason et expires_at ; une exclusion expiree redevient un finding actif.'

new_issue "Codes de sortie et --fail-on" "phase-5,devops" \
'0 OK, 1 seuil depasse, 2 erreur interne.'

new_issue "Labo Terraform vulnerable (S3, IAM, SG)" "phase-6,cloud" \
'main.tf, variables.tf, outputs.tf + vulnerable_s3.tf, vulnerable_iam.tf, vulnerable_sg.tf. default_tags obligatoires, README avec avertissement de cout et rappel terraform destroy.

**DoD** : apply puis scan produit au moins 10 FAIL attendus ; destroy est propre.'

new_issue "Fixtures moto et tests de collectors" "phase-7,tests" \
'conftest.py avec credentials factices en autouse et mock_aws. Un test PASS et un test FAIL par check. Couverture minimale 80 %.'

new_issue "Pipeline GitHub Actions + Dockerfile durci" "phase-8,devops,security" \
'Jobs lint / test / build. Actions epinglees par SHA, permissions minimales, scan Trivy, SBOM. Dockerfile multi-stage, utilisateur non-root.'

new_issue "Historisation SQLite et commande history" "phase-9,data" \
'Schema scans / findings, diff entre deux scans (nouveaux / resolus / persistants), courbe devolution du score, MTTR par severite.'

echo
echo "Termine. Verifie avec : gh issue list"
