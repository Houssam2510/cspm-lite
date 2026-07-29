# 6. Journal de bord et suivi

## 6.1 Pourquoi tenir un journal

Trois raisons concrètes, aucune n'est de la discipline pour la discipline :

1. **Tu retiens ce que tu écris.** Reformuler un concept le jour même le fixe
   durablement ; le relire passivement ne le fixe pas.
2. **Tu produis la matière de ton entretien.** Six mois plus tard, tu ne te
   souviendras pas pourquoi tu as choisi les threads plutôt qu'`asyncio`. Ton journal
   si.
3. **Tu produis la matière de ton article final** (phase 10) sans effort
   supplémentaire.

Règle : 5 à 10 lignes par session, pas plus. Un journal qui devient une corvée est
un journal abandonné.

## 6.2 Modèle d'entrée

Copie ce bloc à chaque session dans `learning/journal/AAAA-MM-JJ.md` :

```markdown
## 2026-08-03 — Phase 2, issue #10 (collector S3)

**Fait** :
-

**Bloqué sur / résolu comment** :
-

**Appris (le truc que je ne savais pas ce matin)** :
-

**Question ouverte** :
-

**Prochaine session** :
-
```

La ligne qui compte le plus est « **Appris** ». Si tu ne peux rien y écrire, la
session était de l'exécution mécanique — ce n'est pas grave de temps en temps, mais
si ça se répète trois fois, change de tâche.

## 6.3 Tableau de progression

Coche au fur et à mesure.

### Phase 0 — Fondations
- [ ] `pyproject.toml` complet, `pip install -e ".[dev]"` fonctionne
- [ ] `ruff` et `mypy` configurés et verts
- [ ] README initial
- [ ] Premier commit sur une branche, première PR

### Phase 1 — Modèle et moteur
- [ ] `models.py` : Severity, Status, Resource, Finding, ScanResult
- [ ] `registry.py` : décorateur `@check` + `get_checks` + `run_checks`
- [ ] Isolation des pannes (un check qui plante n'arrête pas le scan)
- [ ] Scoring de posture
- [ ] Sérialisation JSON testée

### Phase 2 — Auth et collecteurs
- [ ] `auth.py` : session, profil, AssumeRole, `whoami`
- [ ] Retries adaptatifs configurés
- [ ] Interface `Collector`
- [ ] `scan_s3.py`
- [ ] `scan_iam.py` avec credential report
- [ ] `scan_ec2.py` multi-région parallélisé
- [ ] `scan_cloudtrail.py`
- [ ] `AccessDenied` géré proprement

### Phase 3 — Checks
- [ ] 8 checks S3
- [ ] 10 checks IAM
- [ ] 9 checks réseau
- [ ] 6 checks logging
- [ ] Tous mappés CIS, avec remédiation
- [ ] `docs/CHECKS.md` généré automatiquement

### Phase 4 — Reporters
- [ ] JSON versionné
- [ ] Markdown pour PR
- [ ] HTML autonome et présentable
- [ ] ASFF valide

### Phase 5 — CLI
- [ ] `scan`, `list-checks`, `whoami`, `version`
- [ ] Barre de progression Rich
- [ ] `.cspm.yml` avec exclusions datées
- [ ] Exit codes et `--fail-on`

### Phase 6 — Labo Terraform
- [ ] Budget AWS avec alerte posé **avant** tout `apply`
- [ ] `main.tf`, `variables.tf`, `outputs.tf`
- [ ] S3, IAM et SG vulnérables
- [ ] Scan du labo produit les FAIL attendus
- [ ] `terraform destroy` vérifié, aucune ressource orpheline

### Phase 7 — Tests
- [ ] `conftest.py` avec credentials factices en `autouse`
- [ ] Tests de collectors avec moto
- [ ] Un test PASS et un test FAIL par check
- [ ] Couverture > 80 %

### Phase 8 — CI/CD
- [ ] Workflow lint / test / build
- [ ] Actions épinglées par SHA, permissions minimales
- [ ] Dockerfile multi-stage non-root
- [ ] Scan Trivy et SBOM
- [ ] Image publiée sur GHCR

### Phase 9 — Data
- [ ] Persistance SQLite ou Parquet
- [ ] Commande `history` avec diff entre scans
- [ ] Courbe d'évolution du score
- [ ] MTTR et taux de récidive

### Phase 10 — Finition
- [ ] README complet avec capture et GIF
- [ ] Doc d'architecture / ADR
- [ ] Article publié
- [ ] Section CV rédigée
- [ ] Release `v1.0.0` taguée

## 6.4 Auto-évaluation : sais-tu expliquer… ?

À revoir tous les 15 jours. Coche seulement si tu peux répondre **à l'oral, sans
notes, en moins de 2 minutes**.

- [ ] Le modèle de responsabilité partagée
- [ ] Les 4 façons dont un bucket S3 devient public
- [ ] Rôle vs utilisateur IAM, et pourquoi le rôle gagne
- [ ] AssumeRole + ExternalId et le problème du confused deputy
- [ ] L'ordre d'évaluation des policies IAM
- [ ] La chaîne de credentials boto3
- [ ] La brèche Capital One de bout en bout
- [ ] Ce que résout IMDSv2
- [ ] Security group vs NACL
- [ ] Pourquoi la validation d'intégrité CloudTrail existe
- [ ] Ce qu'est le CIS Benchmark et à quoi servent ses sections
- [ ] Ce qu'est l'ASFF et pourquoi tu le produis
- [ ] Pourquoi tu as séparé collecte et évaluation dans ton code
- [ ] Pourquoi des threads et pas des processus pour ton scan
- [ ] Comment tu testes du code AWS sans compte AWS
- [ ] Pourquoi un Dockerfile multi-stage et non-root
- [ ] Pourquoi épingler les actions GitHub par SHA
- [ ] Ce qu'est un SBOM
- [ ] Comment on mesure l'amélioration d'une posture de sécurité

## 6.5 Ressources de référence

**Documentation officielle**
- CIS AWS Foundations Benchmark — cisecurity.org (téléchargement gratuit après
  inscription)
- AWS Security Best Practices / Well-Architected Framework, pilier Sécurité
- Documentation boto3 — boto3.amazonaws.com
- ASFF — docs.aws.amazon.com/securityhub, section « finding format »

**Code à lire** (lire du code d'outil réel vaut dix tutoriels)
- **Prowler** — github.com/prowler-cloud/prowler : regarde `providers/aws/services/`,
  c'est exactement l'architecture que tu construis
- **Scout Suite** — github.com/nccgroup/ScoutSuite : les rulesets en JSON
- **Cartography** — github.com/lyft/cartography : le graphe d'infrastructure, pour
  l'extension attack-path
- **Checkov** — github.com/bridgecrewio/checkov : l'analyse IaC

**Pratique offensive/défensive**
- **flaws.cloud** et **flaws2.cloud** — challenges gratuits de sécurité AWS, à faire
  absolument avant la phase 3, ils donnent l'intuition de l'attaquant
- **CloudGoat** (Rhino Security Labs) — scénarios d'attaque AWS déployés en Terraform
- **AWS Skill Builder** — parcours gratuits, dont un labo sécurité

**Veille**
- tldr.sec (newsletter hebdomadaire, la meilleure du domaine)
- Le blog sécurité AWS
- Les rapports d'incidents de Datadog Security Labs et Wiz Research
