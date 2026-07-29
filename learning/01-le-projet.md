# 1. Le projet : cspm-lite

## 1.1 En une phrase

**cspm-lite** est un scanner de posture de sécurité cloud (CSPM) pour AWS, écrit en
Python : il se connecte en lecture seule à un compte AWS, inventorie les ressources,
évalue des dizaines de règles de sécurité, et produit des rapports exploitables
(JSON, Markdown, HTML, ASFF pour AWS Security Hub).

## 1.2 C'est quoi un CSPM ?

CSPM = *Cloud Security Posture Management*.

Dans le cloud, la majorité des incidents ne viennent pas d'un exploit sophistiqué,
mais d'une **mauvaise configuration** : un bucket S3 laissé public, une clé d'accès
IAM qui traîne depuis 3 ans, un port 22 ouvert sur `0.0.0.0/0`, CloudTrail désactivé
dans une région oubliée. C'est le modèle de **responsabilité partagée** : AWS
sécurise le cloud, toi tu sécurises *dans* le cloud.

Un CSPM automatise la question : *« est-ce que mon compte cloud est configuré
correctement, en continu, selon un référentiel reconnu ? »*

Les outils réels de ce marché :

| Outil | Type | Remarque |
|---|---|---|
| Prowler | Open source, Python | La référence. ~500 checks AWS. |
| Scout Suite | Open source, Python | Sortie HTML, NCC Group. |
| Steampipe / Powerpipe | Open source, Go + SQL | Le cloud vu comme une base SQL. |
| AWS Security Hub | Managed AWS | Agrège les findings au format ASFF. |
| Wiz / Orca / Prisma Cloud | Commercial | CNAPP, agentless, très cher. |

Tu construis une version pédagogique mais **architecturalement honnête** de
Prowler. C'est exactement pour ça que le projet a de la valeur : tu ne réimplémentes
pas un TP, tu reconstruis un outil dont l'industrie se sert.

## 1.3 Pourquoi ce projet est un excellent choix pour toi

Tu es étudiant en génie informatique, intéressé par **cybersécurité + cloud + data**.
Ce projet est l'un des rares qui touche les trois axes en même temps, sans être
artificiel :

- **Cybersécurité** — tu implémentes les contrôles du CIS AWS Foundations Benchmark.
  Tu apprends *pourquoi* chaque misconfiguration est dangereuse, pas juste sa
  détection. C'est du contenu d'entretien direct.
- **Cloud** — tu manipules IAM, S3, EC2/VPC, CloudTrail, KMS, STS via l'API. Tu
  provisionnes ton propre labo en Terraform. Tu comprends la pagination, le
  throttling, le multi-région, l'`AssumeRole`.
- **Data** — tu modélises un schéma de findings, tu normalises des sources
  hétérogènes, tu agrèges, tu scores, tu historises et tu visualises la dérive de
  posture dans le temps. C'est un vrai mini-pipeline ETL.
- **Génie logiciel** — packaging Python, pattern registry/plugins, typage, tests
  avec mocks, CI/CD, Docker, sécurité de la supply chain.

## 1.4 Architecture

```
                 +---------------------+
   AWS API  <--- |   auth.py           |  session boto3, profils, AssumeRole, STS
   (boto3)       +---------------------+
                            |
                            v
                 +---------------------+
                 |   collectors/       |  scan_s3, scan_iam, scan_ec2, scan_cloudtrail
                 |   (EXTRACT)         |  -> pagination, multi-region, parallelisme
                 +---------------------+
                            |
                            v  liste de Resource (modele normalise)
                 +---------------------+
                 |   engine/models.py  |  Resource, Finding, Severity, ScanResult
                 |   (TRANSFORM)       |
                 +---------------------+
                            |
                            v
                 +---------------------+
                 |   engine/registry   |  registre de checks (decorateur @check)
                 |   engine/checks/    |  s3_checks, iam_checks, net_checks, log_checks
                 |   (RULES)           |  -> mappes sur CIS AWS Benchmark
                 +---------------------+
                            |
                            v  liste de Finding
                 +---------------------+
                 |   reporters/        |  json / markdown / html / asff
                 |   (LOAD)            |
                 +---------------------+
                            ^
                            |
                 +---------------------+
                 |   cli.py            |  Typer + Rich, codes de sortie pour la CI
                 +---------------------+

   lab/          Terraform : un compte AWS volontairement vulnerable pour tester
   tests/        pytest + moto : AWS simule, zero cout, zero risque
   .github/      CI : lint, types, tests, build image, scan de l'image
   Dockerfile    image multi-stage, non-root
```

Le point clé de ce design : **collecte et évaluation sont séparées**. Les collectors
ne savent rien de la sécurité, les checks ne savent rien de boto3. C'est ce qui rend
l'outil testable (on injecte de faux inventaires) et extensible (ajouter un check =
ajouter une fonction, pas toucher au reste).

## 1.5 Les composants, fichier par fichier

| Fichier | Rôle | Concept d'ingénierie |
|---|---|---|
| `src/cspm_lite/auth.py` | Créer une session AWS (profil, rôle, région) | Chaîne de credentials, STS, moindre privilège |
| `collectors/scan_s3.py` | Lister buckets + ACL + policy + chiffrement | Pagination, appels par ressource, gestion 404 |
| `collectors/scan_iam.py` | Users, clés, policies, credential report | API asynchrone (rapport à générer puis lire) |
| `collectors/scan_ec2.py` | Security groups, instances, EBS, VPC | Multi-région, parallélisme |
| `collectors/scan_cloudtrail.py` | Trails, config, statut | Détection de la couverture d'audit |
| `engine/models.py` | `Resource`, `Finding`, `Severity`, `ScanResult` | Modélisation de données, typage, sérialisation |
| `engine/registry.py` | Registre de checks via décorateur | Pattern plugin / inversion de contrôle |
| `engine/checks/*.py` | Les règles de sécurité | Référentiel CIS, logique métier pure |
| `reporters/*.py` | Sorties JSON / MD / HTML / ASFF | Formats standards, dataviz |
| `cli.py` | Interface ligne de commande | UX développeur, exit codes, config |
| `lab/*.tf` | Labo AWS vulnérable | Infrastructure as Code |
| `tests/*` | Tests unitaires avec AWS mocké | moto, fixtures, couverture |
| `.github/workflows/ci.yml` | Pipeline d'intégration continue | DevSecOps |
| `Dockerfile` | Packaging conteneurisé | Multi-stage, non-root, supply chain |

## 1.6 Glossaire (à connaître par cœur pour un entretien)

- **Modèle de responsabilité partagée** — AWS sécurise l'infrastructure ; le client
  sécurise ses configurations, données et accès.
- **CIS AWS Foundations Benchmark** — référentiel de ~60 contrôles de sécurité AWS,
  standard de fait. Chaque check que tu écris doit citer son ID CIS.
- **ASFF** (*AWS Security Finding Format*) — le schéma JSON qu'attend AWS Security
  Hub. Produire de l'ASFF = ton outil s'intègre à l'écosystème AWS.
- **Finding** — un résultat d'évaluation : ressource + check + statut (PASS/FAIL) +
  sévérité + remédiation.
- **Sévérité** — CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL (aligne-toi sur ASFF).
- **Moindre privilège** — ton scanner doit tourner avec la policy managée
  `SecurityAudit` (ou `ReadOnlyAccess`), jamais avec `AdministratorAccess`.
- **Confused deputy / AssumeRole + ExternalId** — comment un outil tiers accède à un
  compte client sans clé statique.
- **Drift** — écart entre l'état voulu et l'état réel de l'infrastructure.
- **Shift left** — détecter la misconfiguration au plus tôt (dans la CI, sur le code
  Terraform) plutôt qu'en production.

## 1.7 Règles de sécurité personnelles pour ce projet

1. **Jamais** de clé AWS en clair dans le code, un test, un commit, un screenshot.
   Utilise des profils AWS CLI ou des variables d'environnement.
2. Le labo Terraform crée des ressources **volontairement vulnérables** : compte AWS
   dédié, jamais de données réelles, `terraform destroy` systématique après usage.
3. Mets un **budget AWS** avec alerte à 5 $ dès le jour 1.
4. Ne scanne jamais un compte qui ne t'appartient pas sans autorisation écrite.
5. `.gitignore` couvre déjà `.tfstate`, `.env`, `credentials` — vérifie avant chaque
   `git push` avec `git diff --cached`.
