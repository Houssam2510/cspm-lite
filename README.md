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
                    |
                    v
             history.py            SQLite : tendance, diff, MTTR, recidive
                    ^
                    |
             cli.py                argparse, .cspm.toml, exit codes pour la CI
```

Collecte et évaluation sont **séparées** : les collectors ne savent rien de la
sécurité, les checks ne savent rien de `boto3`. C'est ce qui rend l'outil testable
sans compte AWS et extensible.

## Démonstration en 30 secondes

Aucun compte AWS, aucune credential, aucune dépendance à installer :

```bash
git clone https://github.com/Houssam2510/cspm-lite && cd cspm-lite
PYTHONPATH=src python3 -m cspm_lite.cli scan --demo --format html -o rapport.html
```

Le mode `--demo` évalue les 25 contrôles sur un inventaire fictif reproduisant le labo
Terraform de [`lab/`](lab/). Rapport d'exemple : [`docs/example-report.html`](docs/example-report.html).

## Contrôles

**25 contrôles** implémentés, chacun avec son identifiant CIS, un texte de remédiation
et des tests unitaires. Catalogue complet : [`docs/CHECKS.md`](docs/CHECKS.md).

| Domaine | Contrôles | Exemples |
|---|---|---|
| S3 | 6 | Block Public Access, ACL/policy publique, chiffrement, versioning, TLS obligatoire |
| IAM | 8 | MFA root, clés > 90 jours, credentials dormantes, `AdministratorAccess`, policies `*:*` |
| Réseau | 6 | SSH/RDP/bases exposés (IPv4 **et** IPv6), SG `default`, Flow Logs, EBS, IMDSv2 |
| Logging | 5 | CloudTrail multi-région, validation d'intégrité, KMS, CloudWatch, état réel |

Le mapping CIS vise le *CIS AWS Foundations Benchmark v3.0*.

## Installation

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cspm-lite --help
```

## Usage

```bash
cspm-lite list-checks                      # les 25 contrôles
cspm-lite whoami                           # quel compte vais-je auditer ?
cspm-lite scan --profile mon-profil        # scan complet, sortie Markdown
cspm-lite scan --format html -o rapport.html
cspm-lite scan --service s3 --severity-min HIGH
cspm-lite scan --role-arn arn:aws:iam::123:role/scanner --external-id xyz
cspm-lite scan --format asff -o findings.json   # export AWS Security Hub

cspm-lite init-config                      # ecrire un .cspm.toml d'exemple
cspm-lite scan --save-to posture.db        # historiser le scan
cspm-lite history --db posture.db          # tendance, diff, MTTR, recidive
cspm-lite history --db demo.db --seed-demo --format html -o tendance.html
```

## Configuration et exclusions

Un fichier `.cspm.toml` (cherché en remontant les dossiers, comme `git`) :

```toml
[scan]
severity_min = "LOW"
fail_on      = "HIGH"

[[exclusions]]
check      = "S3-005"
resource   = "arn:aws:s3:::acme-public-assets"
reason     = "bucket de contenus publics : la journalisation d'acces est assumee"
expires_at = 2026-12-31
owner      = "equipe-web"
```

`reason` et `expires_at` sont **obligatoires** : une exception de sécurité sans date
devient permanente et personne ne se souvient pourquoi elle existe. Passée sa date,
l'exclusion cesse de s'appliquer et le finding redevient bloquant. Un finding exclu
reste visible dans le rapport mais sort du score et du code de sortie.

## Suivi dans le temps

```bash
cspm-lite scan --save-to posture.db --fail-on NONE   # a chaque exécution
cspm-lite history --db posture.db --format html -o tendance.html
```

Produit la courbe du score, le diff avec le scan précédent (nouveaux / résolus /
persistants), le **délai moyen de correction** par sévérité et le **taux de
récidive**. Exemple : [`docs/example-history.html`](docs/example-history.html).

On ne pilote pas la sécurité au nombre brut de vulnérabilités — ce chiffre dépend
surtout du périmètre scanné. On la pilote au délai de correction et au taux de
récidive, qui mesurent le processus.

**Codes de sortie**, le contrat avec une CI :

| Code | Signification |
|---|---|
| `0` | aucun finding au-dessus de `--fail-on` |
| `1` | au moins un finding atteint le seuil |
| `2` | erreur d'exécution (credentials, droits, panne) |

## Permissions requises

Le scanner est un outil de **lecture seule**. La policy managée AWS `SecurityAudit`
suffit. Ne lui donnez jamais `AdministratorAccess` : un outil d'audit sur-privilégié
est lui-même le risque.

## Décisions d'architecture

**Une seule dépendance runtime : `boto3`.** La CLI utilise `argparse`, le rendu HTML
n'utilise aucun moteur de template. Pour un outil de sécurité, chaque dépendance est
une surface d'attaque de la chaîne d'approvisionnement.

**Collecte et évaluation strictement séparées.** Les collecteurs ne connaissent pas la
sécurité, les checks ne connaissent pas `boto3`. Conséquence directe : les 25 contrôles
sont testés sans compte AWS ni mock réseau, et ajouter un contrôle est une fonction
décorée, jamais une modification du moteur.

**Isolation des pannes.** Un check qui lève une exception produit un finding
`NOT_AVAILABLE` et le scan continue. En production, un bucket supprimé pendant le scan
ne doit pas interrompre les 24 autres contrôles.

**Rapport HTML autonome.** CSS et JS en ligne, aucune requête externe : ouvrir un
rapport de sécurité ne doit pas divulguer le nom de vos ressources aux logs d'un CDN.

## Tests

```bash
pytest                                              # avec les dépendances de dev
cd tests && PYTHONPATH=../src python3 -m unittest   # sans rien installer
```

217 tests. Les tests de collecteurs utilisent `moto` et se sautent proprement si les
dépendances de dev sont absentes.

## État d'avancement

- [x] Phase 0 — Fondations (packaging, ruff, mypy)
- [x] Phase 1 — Modèle de données et moteur de règles
- [x] Phase 2 — Authentification et collecteurs
- [x] Phase 3 — Les checks de sécurité (25)
- [x] Phase 4 — Reporters (JSON, Markdown, HTML, ASFF)
- [x] Phase 5 — CLI
- [x] Phase 6 — Labo Terraform vulnérable
- [x] Phase 7 — Tests
- [x] Phase 8 — CI/CD et Docker
- [x] Phase 9 — Historisation et métriques de posture
- [x] Phase 10 — Documentation, ADR, gouvernance

## Documentation

- [Décisions d'architecture (ADR)](docs/adr/) — le *pourquoi* de chaque choix
- [Catalogue des contrôles](docs/CHECKS.md)
- [Contribuer](CONTRIBUTING.md) · [Politique de sécurité](SECURITY.md) · [Changelog](CHANGELOG.md)
- [Guide d'apprentissage complet](learning/) — roadmap, concepts, exercices

## Limites connues

Énoncées volontairement, parce qu'un outil de sécurité dont on ignore les angles
morts est plus dangereux que pas d'outil :

- **Pas d'analyse de chemins d'attaque.** Les findings sont isolés ; l'outil ne dit
  pas quel chemin relie une exposition externe à une donnée sensible.
- **Pas de contexte métier**, donc pas de priorisation réelle. Un bucket de logs
  publics est un faux positif que l'outil ne sait pas distinguer.
- **Instantané**, pas de détection temps réel. Le volet CloudTrail événementiel
  serait la suite logique.
- **AWS uniquement**, et les contrôles ne sont pas transposables tels quels.
- **Mono-compte** : pas de support AWS Organizations.

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
