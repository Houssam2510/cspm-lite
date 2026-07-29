# cspm-lite

Scanner de posture de sécurité cloud (CSPM) pour AWS, écrit en Python.

Il se connecte en lecture seule à un compte AWS, inventorie les ressources, évalue des
contrôles du **CIS AWS Foundations Benchmark**, et produit des rapports exploitables
(JSON, Markdown, HTML, ASFF pour AWS Security Hub).

> **Projet en construction.** Ce dépôt est un projet d'apprentissage mené de bout en
> bout : architecture, sécurité cloud, Terraform, tests, CI/CD et analyse de données.
> La roadmap complète est dans [`learning/`](learning/).

## Pourquoi

La majorité des incidents cloud ne viennent pas d'un exploit sophistiqué mais d'une
**mauvaise configuration** : un bucket S3 public, une clé IAM de trois ans, un port 22
ouvert sur `0.0.0.0/0`, CloudTrail désactivé dans une région oubliée. C'est le modèle
de responsabilité partagée : AWS sécurise le cloud, le client sécurise *dans* le cloud.

`cspm-lite` automatise la question : *mon compte est-il configuré correctement, selon
un référentiel reconnu ?*

## Architecture

```
   AWS API  <---  auth.py          session boto3, profils, AssumeRole, STS
   (boto3)          |
                    v
             collectors/           scan_s3, scan_iam, scan_ec2, scan_cloudtrail
             (EXTRACT)             pagination, multi-region, parallelisme
                    |
                    v
             engine/models.py      Resource, Finding, Severity, ScanResult
             (TRANSFORM)
                    |
                    v
             engine/registry       registre de checks (decorateur @check)
             engine/checks/        s3, iam, net, log -> mappes CIS
             (RULES)
                    |
                    v
             reporters/            json / markdown / html / asff
             (LOAD)
                    ^
                    |
             cli.py                Typer + Rich, exit codes pour la CI
```

Collecte et évaluation sont **séparées** : les collectors ne savent rien de la
sécurité, les checks ne savent rien de `boto3`. C'est ce qui rend l'outil testable
sans compte AWS et extensible.

## Contrôles prévus

| Domaine | Contrôles | Exemples |
|---|---|---|
| S3 | 8 | Block Public Access, ACL publique, chiffrement, versioning, TLS obligatoire |
| IAM | 10 | MFA root, clés > 90 jours, `AdministratorAccess`, policies `*:*` |
| Réseau | 9 | SSH/RDP/bases exposés, SG default, VPC Flow Logs, IMDSv2 |
| Logging | 6 | CloudTrail multi-région, validation d'intégrité, chiffrement KMS |

## État d'avancement

- [ ] Phase 0 — Fondations (packaging, ruff, mypy)
- [ ] Phase 1 — Modèle de données et moteur de règles
- [ ] Phase 2 — Authentification et collecteurs
- [ ] Phase 3 — Les checks de sécurité
- [ ] Phase 4 — Reporters
- [ ] Phase 5 — CLI
- [ ] Phase 6 — Labo Terraform vulnérable
- [ ] Phase 7 — Tests (moto)
- [ ] Phase 8 — CI/CD et Docker
- [ ] Phase 9 — Historisation et métriques
- [ ] Phase 10 — Finition et release

## Installation

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cspm-lite --help
```

## Guide d'apprentissage

Le dossier [`learning/`](learning/) contient la démarche complète :

- [Le projet et l'architecture](learning/01-le-projet.md)
- [Roadmap en 10 phases](learning/02-roadmap.md)
- [Backlog de 30 issues](learning/03-issues.md)
- [Fiches de concepts](learning/04-concepts-cles.md)
- [Compétences et valorisation](learning/05-competences-et-valorisation.md)
- [Journal de bord](learning/06-journal-de-bord.md)
- [Maximiser le bagage](learning/07-maximiser-le-bagage.md)
- [**6 exercices avec 153 tests**](learning/exercices/README.md)
- [Le guide complet en PDF](learning/cspm-lite-guide.pdf) (38 pages)

Les exercices tournent sans aucune dépendance :

```bash
bash learning/exercices/verifier.sh
```

## Avertissement

Cet outil est destiné à l'audit de **comptes AWS dont tu es propriétaire ou pour
lesquels tu disposes d'une autorisation écrite**. Le dossier [`lab/`](lab/) provisionne
volontairement des ressources non sécurisées : utilise un compte dédié, sans donnée
réelle, avec un budget et une alerte, et lance `terraform destroy` après chaque
session.

Le scanner doit tourner avec la policy managée `SecurityAudit` — jamais avec
`AdministratorAccess`.

## Licence

MIT — voir [LICENSE](LICENSE).
