# 3. Backlog : 30 issues prêtes à créer

`gh` (GitHub CLI) n'était pas installé sur cette machine, donc je n'ai pas pu lire ni
créer les issues directement. Deux options :

1. **Automatique** — installe `gh`, authentifie-toi, puis lance
   `bash learning/scripts/create_issues.sh`.
   ```bash
   sudo apt install gh        # ou: https://cli.github.com
   gh auth login
   bash learning/scripts/create_issues.sh
   ```
2. **Manuel** — copie-colle les issues ci-dessous dans GitHub.

Labels à créer d'abord : `phase-0` … `phase-10`, `cloud`, `security`, `data`,
`devops`, `tests`, `docs`, `good-first-issue`.

Conseil : crée aussi un **GitHub Project** (vue tableau) avec les colonnes
`Backlog / En cours / En revue / Terminé`. Un board actif visible sur ton profil est
un signal fort pour un recruteur.

---

### Phase 0 — Fondations

**#1 — Remplir `pyproject.toml` et rendre le paquet installable**
`labels: phase-0, devops`
Métadonnées PEP 621, dépendances runtime (`boto3`, `typer`, `rich`, `pydantic`) et
dev (`pytest`, `pytest-cov`, `moto`, `ruff`, `mypy`), layout `src/`, entry point
`cspm-lite = cspm_lite.cli:app`.
*DoD* : `pip install -e ".[dev]"` fonctionne et `import cspm_lite` passe.

**#2 — Configurer ruff et mypy en mode strict**
`labels: phase-0, devops, good-first-issue`
Sections `[tool.ruff]` et `[tool.mypy]` dans `pyproject.toml`. `mypy` en `strict`.
*DoD* : `ruff check . && mypy src` sortent en 0.

**#3 — README initial**
`labels: phase-0, docs, good-first-issue`
Titre, pitch d'une phrase, avertissement légal (usage sur ses propres comptes
uniquement), installation, roadmap en 3 lignes.

---

### Phase 1 — Modèle et moteur

**#4 — `engine/models.py` : Severity, Status, Resource, Finding, ScanResult**
`labels: phase-1, data`
Enums alignés sur ASFF. `Resource` conserve la réponse brute dans `raw`. `ScanResult`
expose `counts_by_severity`, `pass_rate` et `score`.
*DoD* : sérialisation JSON aller-retour testée.

**#5 — `engine/registry.py` : décorateur `@check` et registre**
`labels: phase-1`
`@check(id, title, severity, service, cis, remediation)` enregistre la fonction.
`get_checks(services, severity_min)` filtre. `run_checks(inventory)` exécute.
*DoD* : un check factice est découvert et exécuté par le registre.

**#6 — Isolation des pannes dans le moteur**
`labels: phase-1`
Un check qui lève une exception produit un `Finding` de statut `NOT_AVAILABLE` avec
le message d'erreur, sans interrompre les autres checks.
*DoD* : un test avec un check qui fait `raise` prouve que le scan continue.

**#7 — Scoring de posture**
`labels: phase-1, data`
Score pondéré par sévérité (CRITICAL=10, HIGH=5, MEDIUM=3, LOW=1). Documenter la
formule dans le README.

---

### Phase 2 — Auth et collecteurs

**#8 — `auth.py` : sessions, profils, AssumeRole, STS**
`labels: phase-2, cloud, security`
`get_session(profile, role_arn, external_id, region)`, `whoami()`,
`list_regions()`, retries adaptatifs via `botocore.Config`.
*DoD* : `cspm-lite whoami` affiche l'account id et l'ARN de l'appelant.

**#9 — Interface commune `Collector`**
`labels: phase-2`
Protocol avec `name`, `service`, `collect(session) -> list[Resource]`.

**#10 — `collectors/scan_s3.py`**
`labels: phase-2, cloud`
Buckets + location, public access block, ACL, policy, chiffrement, versioning,
logging. Traiter `NoSuchBucketPolicy` et
`ServerSideEncryptionConfigurationNotFoundError` comme des états normaux.

**#11 — `collectors/scan_iam.py` avec credential report**
`labels: phase-2, cloud, security`
Users, clés + `get_access_key_last_used`, MFA, policies attachées, password policy,
et le credential report (API asynchrone → CSV base64, avec attente et timeout).

**#12 — `collectors/scan_ec2.py` multi-région et parallèle**
`labels: phase-2, cloud`
SG, instances, volumes, VPC, flow logs sur toutes les régions actives via
`ThreadPoolExecutor`. Justifier le choix threads vs processus dans le docstring.
*DoD* : scan complet de 17 régions en moins de 60 s.

**#13 — `collectors/scan_cloudtrail.py`**
`labels: phase-2, cloud`
`describe_trails`, `get_trail_status`, `get_event_selectors`.

**#14 — Gestion du throttling et des permissions manquantes**
`labels: phase-2, cloud`
`AccessDenied` sur un appel ne doit pas tuer le scan : le collector remonte un
avertissement et continue. Documenter la policy IAM minimale requise (`SecurityAudit`).

---

### Phase 3 — Checks de sécurité

**#15 — `s3_checks.py` : 8 checks**
`labels: phase-3, security`
S3-001 à S3-008 (voir `02-roadmap.md`). Chaque check porte son ID CIS, son texte de
remédiation et un lien de référence.
*DoD* : 2 tests par check (un PASS, un FAIL).

**#16 — `iam_checks.py` : 10 checks**
`labels: phase-3, security`
IAM-001 à IAM-010. Le check « clés > 90 jours » doit s'appuyer sur le credential
report, pas sur une heuristique.

**#17 — `net_checks.py` : 9 checks**
`labels: phase-3, security`
NET-001 à NET-009. Traiter les plages CIDR correctement avec le module `ipaddress`
(`0.0.0.0/0` mais aussi `::/0` en IPv6, et les plages trop larges type `/8`).

**#18 — `log_checks.py` : 6 checks**
`labels: phase-3, security`
LOG-001 à LOG-006, mappés sur CIS section 3.

**#19 — Catalogue des checks en Markdown généré**
`labels: phase-3, docs`
Une commande qui génère `docs/CHECKS.md` depuis le registre : id, titre, sévérité,
CIS, remédiation. La doc ne peut plus diverger du code.

---

### Phase 4 — Reporters

**#20 — `json_reporter.py` avec schéma versionné**
`labels: phase-4, data`

**#21 — `markdown_reporter.py` pour les commentaires de PR**
`labels: phase-4, data`
Résumé chiffré en tête, puis détail groupé par sévérité, repliable (`<details>`).

**#22 — `html_reporter.py` : rapport autonome**
`labels: phase-4, data`
Un seul fichier, CSS et JS inline, aucun CDN. Score, répartition par sévérité,
tableau triable et filtrable. Doit rester lisible en mode sombre.

**#23 — `asff_reporter.py` : intégration AWS Security Hub**
`labels: phase-4, cloud, security`
Champs ASFF obligatoires, validation du format contre la doc AWS.

---

### Phase 5 — CLI

**#24 — CLI Typer : `scan`, `list-checks`, `version`, `whoami`**
`labels: phase-5`
Options complètes, barre de progression Rich, sortie colorée.

**#25 — Fichier de configuration `.cspm.yml` et exclusions**
`labels: phase-5, security`
Exclusions avec champs obligatoires `reason` et `expires_at` ; une exclusion expirée
redevient un finding actif.

**#26 — Codes de sortie et `--fail-on`**
`labels: phase-5, devops`
`0` OK, `1` seuil dépassé, `2` erreur interne.

---

### Phase 6 — Labo Terraform

**#27 — Labo Terraform vulnérable (S3, IAM, SG)**
`labels: phase-6, cloud`
`main.tf`, `variables.tf`, `outputs.tf` + les 3 fichiers vulnérables. `default_tags`
obligatoires, README avec avertissement de coût et rappel `terraform destroy`.
*DoD* : `apply` puis scan produit au moins 10 FAIL attendus ; `destroy` est propre.

---

### Phase 7 — Tests

**#28 — Fixtures moto et tests de collectors**
`labels: phase-7, tests`
`conftest.py` avec credentials factices et `mock_aws`. Couverture minimale 80 %.

---

### Phase 8 — CI/CD

**#29 — Pipeline GitHub Actions + Dockerfile durci**
`labels: phase-8, devops, security`
Jobs lint / test / build. Actions épinglées par SHA, permissions minimales, scan
Trivy, SBOM. Dockerfile multi-stage, utilisateur non-root.

---

### Phase 9 — Data

**#30 — Historisation SQLite et commande `history`**
`labels: phase-9, data`
Schéma `scans` / `findings`, diff entre deux scans (nouveaux / résolus / persistants),
courbe d'évolution du score, MTTR par sévérité.

---

## Comment travailler ces issues

- **Une issue = une branche = une pull request.** Même seul sur le projet. Tu
  t'entraînes au workflow réel et ton historique Git devient lisible.
- Nomme les branches `feat/15-s3-checks`, `fix/12-region-timeout`.
- Écris des messages de commit conventionnels : `feat(checks): add S3 public access
  block check`.
- Dans chaque PR, écris 3 lignes : ce que ça fait, pourquoi, comment tu l'as testé.
  C'est un entraînement direct à la revue de code en entreprise.
- Ferme l'issue avec `Closes #15` dans la description de la PR.
