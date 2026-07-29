# 2. Roadmap : les 10 phases

Chaque phase suit le même format :

- **Objectif** — ce que tu produis
- **Étapes** — le découpage concret
- **Ce que tu apprends** — la valeur ajoutée réelle pour ton profil
- **Terminé quand** — la définition de « fini » (DoD), pour ne pas t'éterniser

Ordre recommandé : 0 → 1 → 2 → 3 → 4 → 5 → 7 → 6 → 8 → 9 → 10.
(La phase 7 « tests » arrive tôt volontairement : tester avec `moto` te permet de
développer sans compte AWS. Le labo Terraform, phase 6, coûte de l'argent — tu le
fais quand le code marche déjà.)

Estimation totale : **60 à 90 heures** de travail réel. C'est un projet de semestre,
pas un week-end. Le viser en un week-end est la meilleure façon de l'abandonner.

---

## Phase 0 — Fondations du projet

**Objectif** : un paquet Python installable, propre, avec les outils qualité.

**Étapes**

1. Remplir `pyproject.toml` : métadonnées, dépendances (`boto3`, `typer`, `rich`,
   `pydantic`), dépendances dev (`pytest`, `pytest-cov`, `moto`, `ruff`, `mypy`),
   build-system, layout `src/`, entry point console `cspm-lite = cspm_lite.cli:app`.
2. Créer un environnement virtuel et installer en mode éditable :
   `python -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"`.
3. Configurer `ruff` (lint + format) et `mypy` (mode strict) dans `pyproject.toml`.
4. Écrire un `README.md` minimal : titre, une phrase, badge CI, installation.
5. Vérifier que `import cspm_lite` fonctionne et que `cspm-lite --help` s'exécute.

**Ce que tu apprends**

Le packaging Python moderne (PEP 621, `pyproject.toml`) est une compétence que 80 %
des étudiants n'ont pas : ils écrivent des scripts, pas des paquets. Le layout `src/`
évite la classe de bugs « ça marche chez moi parce que le module est dans le dossier
courant ». `ruff` et `mypy` t'apprennent à écrire du Python typé, ce qui est
maintenant la norme en entreprise.

**Terminé quand** : `pip install -e ".[dev]"`, `ruff check .`, `mypy src` et
`pytest` passent tous les quatre sans erreur.

---

## Phase 1 — Le modèle de données et le moteur

**Objectif** : le cœur logique, indépendant d'AWS. C'est la phase la plus importante
du projet — un mauvais modèle ici pollue tout le reste.

**Étapes**

1. `engine/models.py` :
   - `Severity` — `Enum` : `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`.
   - `Status` — `Enum` : `PASS`, `FAIL`, `WARNING`, `NOT_AVAILABLE`.
   - `Resource` — `id` (ARN), `type` (`AWS::S3::Bucket`), `region`, `account_id`,
     `name`, `tags`, `raw: dict` (la réponse brute de l'API).
   - `Finding` — `check_id`, `title`, `description`, `severity`, `status`,
     `resource`, `remediation`, `references` (liens CIS/doc AWS), `detected_at`.
   - `ScanResult` — `account_id`, `started_at`, `finished_at`, `findings`,
     plus des propriétés calculées : `counts_by_severity`, `pass_rate`, `score`.
2. `engine/registry.py` :
   - un décorateur `@check(id=..., title=..., severity=..., service=..., cis=...)`
     qui enregistre la fonction dans un dictionnaire global ;
   - une fonction `get_checks(services=None, severity_min=None)` pour filtrer ;
   - une fonction `run_checks(inventory) -> list[Finding]` qui exécute et **capture
     les exceptions** (un check qui plante ne doit jamais casser le scan complet).
3. Un check bidon `dummy_always_pass` pour valider la mécanique, plus son test.

**Ce que tu apprends**

- **Modélisation de données** : concevoir un schéma stable qui survivra à 50 checks
  et 4 formats de sortie. C'est du design, pas du code.
- Le **pattern registry** (ou plugin) : le même mécanisme que les routes Flask
  (`@app.route`), les fixtures pytest, les tâches Celery. Comprendre le décorateur qui
  enregistre est un vrai palier en Python.
- **Isolation des pannes** : un moteur de règles robuste ne s'arrête pas au premier
  crash. C'est une réflexion d'ingénieur, pas d'étudiant.

**Terminé quand** : tu peux enregistrer un check avec un décorateur, l'exécuter via
`run_checks()`, obtenir un `Finding`, et le sérialiser en JSON — sans qu'aucune ligne
de `boto3` n'existe encore dans le projet.

---

## Phase 2 — Authentification et collecteurs

**Objectif** : parler à l'API AWS proprement.

**Étapes**

1. `auth.py` :
   - `get_session(profile=None, role_arn=None, region=None)` qui retourne une
     `boto3.Session` ;
   - support de l'`AssumeRole` via STS (avec `ExternalId` optionnel) ;
   - `whoami()` via `sts.get_caller_identity()` → account_id, ARN de l'appelant ;
   - `list_regions()` via EC2 pour le scan multi-région ;
   - une config `botocore.Config` avec `retries={"mode": "adaptive", "max_attempts": 10}`.
2. `collectors/scan_s3.py` : `list_buckets`, puis pour chaque bucket
   `get_bucket_location`, `get_public_access_block`, `get_bucket_acl`,
   `get_bucket_policy`, `get_bucket_encryption`, `get_bucket_versioning`,
   `get_bucket_logging`. Gérer les `ClientError` (`NoSuchBucketPolicy`,
   `ServerSideEncryptionConfigurationNotFoundError` sont *normales*, pas des bugs).
3. `collectors/scan_iam.py` : users, access keys + `get_access_key_last_used`,
   MFA devices, policies attachées, `get_account_password_policy`, et surtout le
   **credential report** (`generate_credential_report` puis `get_credential_report`,
   avec attente active — l'API est asynchrone et retourne un CSV en base64).
4. `collectors/scan_ec2.py` : `describe_security_groups`, `describe_instances`,
   `describe_volumes`, `describe_vpcs`, `describe_flow_logs` — pour **toutes** les
   régions, en parallèle avec `concurrent.futures.ThreadPoolExecutor`.
5. `collectors/scan_cloudtrail.py` : `describe_trails`, `get_trail_status`,
   `get_event_selectors`.
6. Un `Collector` protocol/ABC commun : `name`, `service`, `collect(session) -> list[Resource]`.

**Ce que tu apprends**

- **L'API cloud dans la vraie vie** : la pagination (`get_paginator`), le throttling
  et le backoff exponentiel, les erreurs qui ne sont pas des erreurs, les endpoints
  globaux (IAM, S3 ListBuckets) contre régionaux.
- **La concurrence en Python** : le scan multi-région est *I/O bound*, donc les
  threads sont le bon outil (le GIL n'est pas un problème ici). Savoir expliquer
  pourquoi threads et pas `multiprocessing` est une question d'entretien classique.
- **IAM en profondeur** : la chaîne de credentials boto3, `AssumeRole`, les
  credentials temporaires STS, le problème du *confused deputy* et pourquoi
  l'`ExternalId` existe.
- **Le credential report** : une API asynchrone qui rend un CSV base64. C'est
  inélégant et c'est exactement le genre de chose qu'on rencontre en entreprise.

**Terminé quand** : `cspm-lite scan --profile lab --dry-run` liste tes ressources
réelles sur toutes les régions actives, sans crash, en moins de 60 secondes.

---

## Phase 3 — Les checks de sécurité (le cœur du projet)

**Objectif** : 25 à 35 règles, chacune mappée sur un contrôle CIS.

Pour **chaque** check, écris systématiquement : l'ID CIS, le risque réel (« ce qui
peut arriver »), la remédiation, et un test unitaire. Un check sans explication du
risque n'a aucune valeur pédagogique.

### `s3_checks.py`

| ID | Check | Risque |
|---|---|---|
| S3-001 | Block Public Access activé (4 flags) | Fuite de données publique |
| S3-002 | ACL n'accorde rien à `AllUsers` / `AuthenticatedUsers` | Bucket lisible par le monde |
| S3-003 | Bucket policy sans `Principal: "*"` sans condition | Idem, via policy |
| S3-004 | Chiffrement par défaut activé (SSE-S3 ou SSE-KMS) | Données au repos en clair |
| S3-005 | Versioning activé | Pas de récupération après ransomware/suppression |
| S3-006 | Access logging activé | Aucune trace d'accès en cas d'incident |
| S3-007 | Policy imposant TLS (`aws:SecureTransport: false` → Deny) | Données en transit en clair |
| S3-008 | MFA Delete activé (bonus) | Suppression d'objets sans second facteur |

### `iam_checks.py`

| ID | Check | Risque | CIS |
|---|---|---|---|
| IAM-001 | Le compte root n'a pas de clé d'accès | Compromission totale du compte | 1.4 |
| IAM-002 | MFA activé sur le root | Idem | 1.5 |
| IAM-003 | MFA activé sur tous les utilisateurs console | Vol de mot de passe = accès | 1.10 |
| IAM-004 | Aucune clé d'accès de plus de 90 jours | Fenêtre d'exposition | 1.14 |
| IAM-005 | Aucune credential inutilisée depuis 45 jours | Surface d'attaque dormante | 1.12 |
| IAM-006 | Politique de mot de passe conforme (14 car., etc.) | Force brute | 1.8 |
| IAM-007 | Aucun utilisateur avec `AdministratorAccess` attaché directement | Violation du moindre privilège | 1.16 |
| IAM-008 | Aucune policy custom avec `Action: "*"` + `Resource: "*"` | Escalade de privilèges | 1.16 |
| IAM-009 | Support role existant | Réponse à incident | 1.17 |
| IAM-010 | Une seule clé active par utilisateur | Gestion des secrets | — |

### `net_checks.py`

| ID | Check | Risque |
|---|---|---|
| NET-001 | Aucun SG n'ouvre le port 22 sur `0.0.0.0/0` | SSH exposé, force brute |
| NET-002 | Idem pour 3389 (RDP) | RDP exposé |
| NET-003 | Idem pour 3306/5432/27017/6379 (bases) | Base de données exposée |
| NET-004 | Aucun SG avec `-1` (tous ports) sur `0.0.0.0/0` | Ouverture totale |
| NET-005 | Le security group `default` n'autorise aucun trafic | CIS 5.3 |
| NET-006 | VPC Flow Logs activés sur tous les VPC | Aucune visibilité réseau |
| NET-007 | Volumes EBS chiffrés | Données au repos |
| NET-008 | Pas d'IP publique sur les instances non prévues | Exposition |
| NET-009 | IMDSv2 obligatoire sur les instances EC2 | SSRF → vol de credentials |

`NET-009` mérite une attention particulière : c'est la faille de la brèche Capital
One (2019, 100 millions de dossiers clients). Une SSRF permettait de lire les
credentials IAM depuis `169.254.169.254`. IMDSv2 corrige ça. Sache raconter cette
histoire en entretien.

### `log_checks.py`

| ID | Check | Risque | CIS |
|---|---|---|---|
| LOG-001 | Au moins un trail CloudTrail multi-région activé | Aucun audit | 3.1 |
| LOG-002 | Validation d'intégrité des fichiers de log activée | Falsification des logs | 3.2 |
| LOG-003 | Le bucket des logs CloudTrail n'est pas public | Fuite des logs d'audit | 3.3 |
| LOG-004 | Logs chiffrés avec KMS | Confidentialité | 3.5 |
| LOG-005 | Intégration CloudWatch Logs | Pas d'alerte temps réel | 3.4 |
| LOG-006 | Accès en écriture au bucket de logs journalisé | Traçabilité | 3.6 |

**Ce que tu apprends**

C'est ici que se concentre la valeur cybersécurité. Tu n'apprends pas « du Python » :
tu apprends **pourquoi** un bucket public a coûté des dizaines de millions à
Capital One, Accenture, Verizon ; **pourquoi** une clé de 3 ans est le premier
vecteur d'attaque cloud ; **comment** un attaquant enchaîne SSRF → IMDS → credentials
→ `AssumeRole` → exfiltration. Tu construis un vocabulaire d'entretien que très peu
d'étudiants possèdent.

Tu apprends aussi à lire un **référentiel de conformité** et à le traduire en code —
c'est littéralement le métier d'un ingénieur GRC/Cloud Security.

**Terminé quand** : au moins 25 checks implémentés, chacun avec son ID CIS, son texte
de remédiation et son test unitaire.

---

## Phase 4 — Les reporters

**Objectif** : transformer une liste de findings en quelque chose d'utilisable.

**Étapes**

1. `json_reporter.py` — sortie machine, schéma stable, versionné (`schema_version`).
2. `markdown_reporter.py` — tableau récapitulatif + détail par sévérité. C'est ce
   qu'on colle dans un commentaire de pull request.
3. `html_reporter.py` — un fichier HTML autonome (CSS et JS inline, aucune
   dépendance externe) : score global, répartition par sévérité, tableau filtrable,
   détail dépliable par finding.
4. `asff_reporter.py` — format AWS Security Hub : `SchemaVersion`, `Id`, `ProductArn`,
   `GeneratorId`, `Types`, `Severity.Label`, `Resources[]`, `Compliance.Status`,
   `Remediation.Recommendation`. Valide le résultat contre la doc AWS.
5. Un **scoring de posture** : par exemple
   `score = 100 * somme(poids des PASS) / somme(poids de tous)`, où le poids dépend
   de la sévérité (CRITICAL=10, HIGH=5, MEDIUM=3, LOW=1).

**Ce que tu apprends**

- La **séparation données / présentation** : un même `ScanResult`, quatre sorties.
- L'**interopérabilité** : produire de l'ASFF, c'est comprendre qu'un outil ne vit
  pas seul mais dans un écosystème. C'est la différence entre un script et un produit.
- La **dataviz** : choisir ce qu'on montre. Un rapport avec 300 findings non triés
  est inutile ; un rapport avec « 3 critiques, voici lesquelles » est actionnable.
  La règle : un rapport doit répondre à « qu'est-ce que je corrige en premier ? ».

**Terminé quand** : `cspm-lite scan --format html -o report.html` produit un fichier
que tu serais fier de montrer à un recruteur, sans retouche.

---

## Phase 5 — La CLI

**Objectif** : une interface que quelqu'un d'autre que toi peut utiliser.

**Étapes**

1. `cli.py` avec **Typer** :
   - `scan` — options `--profile`, `--role-arn`, `--region` (répétable), `--service`,
     `--severity-min`, `--format`, `--output`, `--fail-on`.
   - `list-checks` — tableau Rich de tous les checks (id, service, sévérité, CIS).
   - `version`.
2. Une barre de progression **Rich** pendant la collecte.
3. Fichier de configuration `.cspm.yml` : checks désactivés, ressources exclues
   (allowlist avec justification et date d'expiration), sévérité minimale.
4. **Codes de sortie** : `0` = OK, `1` = findings au-dessus du seuil `--fail-on`,
   `2` = erreur d'exécution. C'est ce qui permet d'utiliser l'outil dans une CI.
5. Logging structuré avec `--verbose` / `--quiet`.

**Ce que tu apprends**

- L'**UX développeur** : la différence entre un outil qu'on utilise et un script
  qu'on abandonne tient souvent aux messages d'erreur et aux valeurs par défaut.
- Les **exit codes** : c'est le contrat entre ton outil et n'importe quel pipeline.
- La **gestion d'exceptions par allowlist** : toute exception de sécurité doit être
  documentée, justifiée et datée. C'est une notion de gouvernance, pas de code.

**Terminé quand** : `cspm-lite --help` est compréhensible sans lire le code, et
`cspm-lite scan --fail-on HIGH` renvoie bien `1` quand il trouve un finding HIGH.

---

## Phase 6 — Le labo Terraform

**Objectif** : une infrastructure AWS volontairement vulnérable, reproductible,
détruite en une commande.

Attention : **cette phase crée de vraies ressources AWS et peut coûter de l'argent.**
Fais-la après la phase 7 (tests avec moto), et pose un budget avec alerte avant.

**Étapes**

1. `main.tf` — provider AWS, `required_version`, `default_tags`
   (`Project = "cspm-lite-lab"`, `Owner`, `AutoDelete = "true"`).
2. `variables.tf` — région, préfixe de nommage, flag `enable_expensive_resources`.
3. `vulnerable_s3.tf` — un bucket sans Block Public Access, sans chiffrement, sans
   versioning, avec une policy publique en lecture.
4. `vulnerable_iam.tf` — un utilisateur avec `AdministratorAccess`, une policy custom
   `"Action": "*"` / `"Resource": "*"`, une clé d'accès, aucun MFA.
5. `vulnerable_sg.tf` — un security group avec 22, 3389 et 3306 ouverts sur
   `0.0.0.0/0`.
6. `outputs.tf` — les identifiants des ressources créées, pour les tests.
7. Un `README` de labo : `terraform init/plan/apply`, puis **toujours**
   `terraform destroy`.

**Ce que tu apprends**

- **Terraform** est probablement la compétence la plus demandée sur le marché cloud
  après le cloud lui-même. Tu apprends le cycle `plan/apply/destroy`, l'état, les
  variables, les outputs, le graphe de dépendances.
- Le **couple attaque/défense** : tu crées la vulnérabilité *et* le détecteur. Tu
  vérifies que ton check S3-001 lève bien un FAIL sur ton bucket. C'est la boucle de
  validation d'un vrai outil de sécurité.
- La **gestion des coûts cloud** (FinOps) : tags, budget, destruction systématique.
  Savoir dire « j'ai posé un budget et un tag AutoDelete » impressionne en entretien.

**Terminé quand** : `terraform apply` puis `cspm-lite scan` produit au moins 10
findings FAIL attendus, et `terraform destroy` ne laisse rien derrière.

---

## Phase 7 — Tests et qualité

**Objectif** : développer sans compte AWS, et prouver que ça marche.

**Étapes**

1. `conftest.py` — fixtures : credentials AWS factices (variables d'environnement),
   décorateur `mock_aws` de **moto**, inventaires d'exemple.
2. `test_collectors.py` — avec moto : créer un bucket, lancer le collector, vérifier
   la `Resource` produite.
3. `test_checks.py` — tests **purs**, sans AWS : on injecte un inventaire fabriqué à
   la main et on vérifie le `Finding`. Un test PASS *et* un test FAIL par check.
4. `pytest.ini` / config dans `pyproject.toml` : couverture minimale à 80 %
   (`--cov=cspm_lite --cov-fail-under=80`).
5. Tests paramétrés (`@pytest.mark.parametrize`) pour les variantes de ports dans
   les checks réseau.

**Ce que tu apprends**

- **moto** : simuler AWS en local. C'est la technique qui permet de développer du
  code cloud sans facture ni risque, et c'est utilisé partout en entreprise.
- La **pyramide de tests** : beaucoup de tests unitaires rapides sur la logique pure
  (les checks), peu de tests d'intégration lents (les collectors). Ton architecture
  de la phase 1 rend ça possible — c'est le retour sur investissement du design.
- La **couverture** comme indicateur, pas comme objectif.

**Terminé quand** : `pytest --cov` passe à plus de 80 %, et tu peux développer un
nouveau check de bout en bout sans jamais toucher à AWS.

---

## Phase 8 — CI/CD, Docker et supply chain

**Objectif** : industrialiser.

**Étapes**

1. `.github/workflows/ci.yml` :
   - déclencheurs `push` et `pull_request` ;
   - job `lint` : `ruff check`, `ruff format --check`, `mypy src` ;
   - job `test` : matrice Python 3.11 / 3.12, upload de la couverture ;
   - job `build` : image Docker, scan **Trivy**, génération d'un **SBOM**
     (`anchore/sbom-action`), publication sur GHCR sur la branche `master` ;
   - permissions minimales (`permissions: contents: read`), actions **épinglées par
     SHA** et non par tag.
2. `Dockerfile` multi-stage : un stage `builder` qui installe les dépendances, un
   stage final `python:3.12-slim` avec seulement le nécessaire, utilisateur
   non-root, `HEALTHCHECK`, `ENTRYPOINT ["cspm-lite"]`.
3. Un workflow bonus `security.yml` : `pip-audit` sur les dépendances +
   **Dependabot**.

**Ce que tu apprends**

- **DevSecOps concret** : la sécurité intégrée au pipeline plutôt qu'ajoutée après.
- La **sécurité de la supply chain** : épingler les actions par SHA empêche un
  attaquant ayant compromis un tag d'exécuter du code dans ta CI. Le SBOM répond à
  « quelles dépendances ai-je réellement ? » — la question posée après Log4Shell.
- Le **Dockerfile multi-stage et non-root** : deux réflexes que beaucoup de
  développeurs seniors n'ont toujours pas.

**Terminé quand** : le badge CI est vert sur le README, et `docker run ghcr.io/<toi>/cspm-lite --help` fonctionne.

---

## Phase 9 — Le volet data

**Objectif** : passer d'un scan ponctuel à un suivi de posture dans le temps. C'est
la phase qui différencie ton projet de tous les clones de Prowler.

**Étapes**

1. Persistance des scans : une base **SQLite** (ou des fichiers **Parquet** +
   **DuckDB**) avec un schéma `scans` / `findings`.
2. Une commande `cspm-lite history` : évolution du score, findings nouveaux, findings
   résolus, findings persistants entre deux scans (un `diff` de posture).
3. Des métriques de sécurité réelles :
   - **MTTR** — temps moyen de remédiation par sévérité ;
   - **taux de récidive** — findings qui réapparaissent après correction ;
   - **backlog par service** — où se concentre la dette de sécurité.
4. Un notebook Jupyter ou un dashboard HTML de tendance (score dans le temps,
   top 10 des checks les plus en échec).
5. Bonus : export vers Prometheus/OpenMetrics pour un dashboard Grafana.

**Ce que tu apprends**

- Un vrai **mini-pipeline data** : ingestion → normalisation → stockage colonnaire →
  agrégation → visualisation. C'est de l'analytics engineering.
- La **modélisation temporelle** : distinguer l'état (snapshot) de l'événement
  (apparition/disparition d'un finding) est le cœur de la modélisation dimensionnelle.
- Les **métriques de sécurité** : savoir qu'on pilote la sécurité au MTTR et au taux
  de récidive, pas au nombre brut de vulnérabilités, est un raisonnement de manager.

**Terminé quand** : tu peux produire un graphique montrant l'évolution du score de
posture sur au moins 5 scans successifs.

---

## Phase 10 — Finition et valorisation

**Objectif** : que le projet serve ta carrière.

**Étapes**

1. `README.md` complet : problème résolu, capture d'écran du rapport HTML, GIF de
   démo (`asciinema` ou `vhs`), installation, usage, liste des checks, architecture,
   avertissement légal.
2. Une **documentation d'architecture** : 1 à 2 pages expliquant *pourquoi* collecte
   et évaluation sont séparées, quels compromis tu as faits (ADR — Architecture
   Decision Records).
3. Un **article** (blog, LinkedIn, Medium) : « J'ai construit un CSPM en Python pour
   comprendre la sécurité AWS de l'intérieur ». Raconte un check en détail, avec
   l'incident réel qu'il aurait évité.
4. Une **section CV** de 3 lignes (voir `05-competences-et-valorisation.md`).
5. Un **tag de release** `v1.0.0` et une page GitHub Releases.

**Ce que tu apprends**

Un projet non raconté n'existe pas. Savoir expliquer ton architecture en 3 minutes
vaut autant que l'avoir codée. Écrire l'article te force à vérifier que tu as
vraiment compris.

**Terminé quand** : un inconnu peut cloner, installer, lancer et comprendre le projet
en moins de 10 minutes, sans te poser de question.

---

## Récapitulatif

| Phase | Sujet | Effort | Axe dominant |
|---|---|---|---|
| 0 | Fondations | 3-5 h | Génie logiciel |
| 1 | Modèle + moteur | 6-8 h | Génie logiciel / Data |
| 2 | Auth + collectors | 10-14 h | Cloud |
| 3 | Checks de sécurité | 15-20 h | **Cybersécurité** |
| 4 | Reporters | 6-8 h | Data |
| 5 | CLI | 4-6 h | Génie logiciel |
| 6 | Labo Terraform | 5-7 h | Cloud / IaC |
| 7 | Tests | 6-8 h | Génie logiciel |
| 8 | CI/CD + Docker | 5-7 h | DevSecOps |
| 9 | Volet data | 8-12 h | **Data** |
| 10 | Finition | 4-6 h | Communication |
