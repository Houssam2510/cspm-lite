# Journal des modifications

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).
Versionnage sémantique.

## [Non publié]

## [0.1.0] — 2026-07-30

Première version fonctionnelle de bout en bout.

### Ajouté

- **Moteur** : modèle de données pur (`Inventory`, `Finding`, `ScanResult`), registre
  de contrôles par décorateur, isolation des pannes, score de posture pondéré par
  sévérité.
- **25 contrôles** mappés sur le CIS AWS Foundations Benchmark v3.0 : 6 S3, 8 IAM,
  6 réseau, 5 CloudTrail. Chacun avec identifiant CIS, remédiation et tests.
- **Collecteurs** S3, IAM (via credential report), EC2/VPC et CloudTrail. Pagination
  systématique, scan multi-région parallélisé, gestion des `AccessDenied`.
- **Reporters** JSON versionné, Markdown pour commentaires de PR, HTML autonome
  (aucune requête externe, thème clair et sombre), ASFF pour AWS Security Hub.
- **CLI** `scan`, `list-checks`, `whoami`, `history`, `init-config`. Codes de sortie
  0/1/2 pour intégration en CI.
- **Mode `--demo`** : scan complet sans compte AWS ni credentials.
- **Configuration** `.cspm.toml` avec exclusions exigeant justification et date
  d'expiration.
- **Historisation** SQLite : tendance du score, diff entre scans, délai moyen de
  correction par sévérité, taux de récidive.
- **Labo Terraform** volontairement vulnérable, avec bucket témoin conforme et rôle
  scanner en lecture seule.
- **Docker** multi-stage non-root ; **CI** avec actions épinglées par SHA, Trivy et
  SBOM.
- 217 tests, exécutables avec `pytest` ou avec la seule bibliothèque standard.

### Limites connues

- Pas d'analyse de chemins d'attaque : les findings sont isolés, sans le graphe qui
  relie une exposition à une donnée sensible.
- Pas de contexte métier, donc pas de priorisation réelle : un bucket de logs publics
  est un faux positif que l'outil ne sait pas distinguer.
- Instantané, pas de détection temps réel.
- AWS uniquement.
- Support multi-comptes via AWS Organizations non implémenté.
