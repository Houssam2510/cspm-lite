# 4. Fiches de concepts clés

Ces fiches sont ce que tu dois pouvoir expliquer **sans notes**. Chacune correspond
à une question posée en entretien de stage/alternance cloud ou cybersécurité.

---

## 4.1 Le modèle de responsabilité partagée

AWS est responsable de la sécurité **du** cloud : datacenters, hyperviseur, réseau
physique, disponibilité des services managés.
Toi tu es responsable de la sécurité **dans** le cloud : IAM, configuration des
services, chiffrement, données, patchs de tes instances.

Corollaire : quasiment toutes les brèches cloud médiatisées sont des erreurs client,
pas des failles AWS. C'est précisément le créneau d'un CSPM.

**Question type** : « Qui est responsable si un bucket S3 fuit ? » → le client, sans
ambiguïté. S3 est privé par défaut depuis toujours ; le rendre public est une action
délibérée.

---

## 4.2 IAM : les 6 notions à maîtriser

1. **Principal** — qui agit (user, rôle, service).
2. **Policy** — un document JSON `Effect / Action / Resource / Condition`. Il en
   existe plusieurs types : identity-based (attachée à un principal), resource-based
   (attachée à la ressource, ex. bucket policy), SCP (au niveau de l'organisation),
   permission boundary.
3. **Évaluation** — un `Deny` explicite gagne toujours. Sans `Allow` explicite,
   c'est refusé. L'ordre : Deny explicite > SCP > boundary > Allow.
4. **Rôle vs utilisateur** — un rôle n'a pas de credentials permanents ; on
   l'*assume* via STS et on reçoit des credentials temporaires. **C'est toujours la
   bonne réponse.** Un utilisateur IAM avec clé statique est un anti-pattern.
5. **AssumeRole + ExternalId** — quand un outil tiers (comme un CSPM SaaS) accède à
   ton compte, tu crées un rôle qu'il assume. L'`ExternalId` empêche le *confused
   deputy* : sans lui, un autre client du même prestataire pourrait deviner ton ARN
   et se faire accéder à ton compte par le prestataire.
6. **Moindre privilège** — ton scanner doit tourner avec `SecurityAudit`, une policy
   managée AWS en lecture seule orientée audit. Si tu demandes `AdministratorAccess`
   pour un outil de lecture, tu es toi-même le risque.

**Chaîne de credentials boto3** (ordre de résolution) : paramètres explicites →
variables d'environnement → fichier `~/.aws/credentials` → rôle du conteneur
(ECS) → rôle de l'instance (IMDS). Savoir réciter cet ordre est une question
d'entretien fréquente.

---

## 4.3 S3 : pourquoi les buckets fuient

Quatre mécanismes rendent un bucket public, et il faut les vérifier tous :

1. **ACL** — l'ancien mécanisme. `AllUsers` = tout Internet. `AuthenticatedUsers` =
   **n'importe quel compte AWS au monde**, pas « mes utilisateurs » — c'est le piège
   classique.
2. **Bucket policy** — `"Principal": "*"` sans `Condition`.
3. **Block Public Access** — 4 flags (`BlockPublicAcls`, `IgnorePublicAcls`,
   `BlockPublicPolicy`, `RestrictPublicBuckets`). Activés, ils neutralisent 1 et 2.
   À activer au niveau du compte, pas seulement du bucket.
4. **Website hosting / presigned URLs** — moins fréquent mais réel.

Autres contrôles importants : chiffrement au repos (SSE-S3 gratuit, SSE-KMS pour la
traçabilité des accès à la clé), versioning (récupération après suppression ou
ransomware), access logging, et une policy qui refuse `aws:SecureTransport: false`
pour imposer TLS.

**Incidents réels à citer** : Capital One (2019), Accenture (2017), Verizon (2017),
Booz Allen Hamilton (2017) — tous des buckets mal configurés.

---

## 4.4 Réseau : security groups et NACL

- **Security Group** — pare-feu **stateful** au niveau de l'interface réseau.
  Autorise uniquement (pas de règle deny). Le trafic retour est automatiquement
  permis.
- **NACL** — pare-feu **stateless** au niveau du sous-réseau. Autorise et refuse.
  Il faut ouvrir explicitement le retour (ports éphémères).

Les erreurs qui comptent :
- `0.0.0.0/0` sur 22 (SSH) ou 3389 (RDP) — force brute garantie en quelques minutes ;
  la bonne réponse moderne est **AWS Systems Manager Session Manager**, qui supprime
  le besoin d'ouvrir SSH.
- `0.0.0.0/0` sur 3306, 5432, 27017, 6379 — base de données exposée à Internet.
- Le SG `default` laissé permissif : il s'applique par défaut à toute nouvelle
  ressource dont on oublie de spécifier le SG.
- Absence de **VPC Flow Logs** : après un incident, tu n'as aucune trace réseau.

---

## 4.5 IMDS et la brèche Capital One

Une instance EC2 peut lire ses propres credentials IAM temporaires sur
`http://169.254.169.254/latest/meta-data/iam/security-credentials/`.

En 2019, Capital One : une application web derrière un WAF mal configuré était
vulnérable à une **SSRF**. L'attaquante a fait interroger cette adresse par le
serveur, récupéré les credentials du rôle de l'instance — un rôle sur-privilégié —
et exfiltré 100 millions de dossiers clients depuis S3. Amende : 80 millions de
dollars.

**IMDSv2** corrige la classe de faille : il exige un token obtenu par une requête
`PUT` avec un en-tête spécifique, ce qu'une SSRF simple ne peut pas produire. Rendre
IMDSv2 obligatoire (`HttpTokens: required`) est le check NET-009.

Cette histoire contient trois leçons : SSRF, moindre privilège du rôle d'instance, et
défense en profondeur. Sache la raconter en 90 secondes.

---

## 4.6 CloudTrail : sans logs, pas d'investigation

CloudTrail enregistre chaque appel d'API du compte. Sans lui, une intrusion est
invisible et non-investigable.

Les points de contrôle :
- **Multi-région** — sinon un attaquant opère depuis une région non surveillée.
- **Validation d'intégrité des fichiers** — signature qui détecte l'altération des
  logs *a posteriori*. Un attaquant qui efface ses traces est détecté.
- **Bucket de logs non public et journalisé**.
- **Chiffrement KMS**.
- **Intégration CloudWatch Logs** — pour alerter en temps réel, pas juste archiver.

Différence à connaître : **CloudTrail** = plan de contrôle (qui a fait quoi sur
l'API). **VPC Flow Logs** = plan réseau. **S3 access logs / CloudTrail data events**
= plan données (qui a lu quel objet). Les trois sont complémentaires.

---

## 4.7 Le CIS AWS Foundations Benchmark

Un document public du Center for Internet Security, ~60 contrôles numérotés par
section :
- **1.x** — IAM
- **2.x** — Stockage (S3, EBS, RDS)
- **3.x** — Logging (CloudTrail, Config)
- **4.x** — Monitoring (alarmes CloudWatch)
- **5.x** — Réseau (VPC, security groups)

Chaque contrôle a un niveau (Level 1 = essentiel, Level 2 = renforcé), un rationnel,
une procédure d'audit et une procédure de remédiation.

**Pourquoi c'est important pour toi** : quand tu écris `cis="1.14"` sur ton check,
tu ne fais pas de la décoration. Tu transformes ton outil en outil de **conformité**,
et tu apprends le vocabulaire GRC (gouvernance, risque, conformité) que les
entreprises utilisent. Autres référentiels à connaître de nom : NIST CSF, ISO 27001,
PCI-DSS, SOC 2, et pour ton profil au Maroc/en France : la directive NIS2 et le RGPD.

---

## 4.8 ASFF : parler la langue de l'écosystème

Le *AWS Security Finding Format* est le schéma JSON de Security Hub. Champs
essentiels : `SchemaVersion`, `Id`, `ProductArn`, `GeneratorId`, `AwsAccountId`,
`Types`, `CreatedAt`, `Severity.Label`, `Title`, `Description`, `Resources[]`,
`Compliance.Status`, `Remediation.Recommendation.Text`.

L'intérêt pédagogique : comprendre que la valeur d'un outil de sécurité ne vient pas
seulement de ce qu'il détecte, mais de sa capacité à **s'insérer dans un flux
existant** (SIEM, ticketing, Security Hub). Un outil qui produit un format
propriétaire finit ignoré.

---

## 4.9 boto3 : les pièges de l'API AWS

- **Pagination** — `list_*` et `describe_*` renvoient souvent 50 ou 100 éléments
  maximum. Utilise toujours `client.get_paginator("list_users").paginate()`, jamais
  l'appel brut. C'est le bug numéro 1 des scripts AWS amateurs.
- **Throttling** — l'API renvoie `Throttling` / `RequestLimitExceeded` en cas de
  rafale. Configure `Config(retries={"mode": "adaptive", "max_attempts": 10})`.
- **Erreurs qui n'en sont pas** — `NoSuchBucketPolicy`,
  `ServerSideEncryptionConfigurationNotFoundError`,
  `NoSuchPublicAccessBlockConfiguration` signifient simplement « pas configuré ».
  Les traiter comme des exceptions fatales rend l'outil inutilisable.
- **Global vs régional** — IAM et `s3:ListBuckets` sont globaux ; EC2, CloudTrail,
  et les opérations par bucket sont régionaux. Un bucket doit être interrogé dans sa
  région d'origine.
- **Client vs Resource** — l'API `resource` est plus jolie mais incomplète et en
  maintenance réduite. Utilise `client` pour un outil sérieux.

---

## 4.10 moto : simuler AWS en local

`moto` intercepte les appels boto3 et simule les services AWS en mémoire.

```python
from moto import mock_aws

@mock_aws
def test_public_bucket_is_flagged():
    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="leaky")
    ...
```

Prérequis absolu : mettre de **fausses credentials** dans l'environnement du test
(`AWS_ACCESS_KEY_ID=testing`, etc.) via une fixture `autouse`. Sinon, si moto
échoue à intercepter, ton test taperait sur ton vrai compte AWS. C'est un piège
classique et dangereux.

Limite : moto ne simule pas tout (le credential report IAM, par exemple, est
partiel). Pour ces cas, teste la logique de parsing séparément avec un CSV d'exemple
en fixture — ce qui prouve encore une fois l'intérêt d'avoir séparé collecte et
évaluation.

---

## 4.11 Terraform : le vocabulaire minimum

- **Provider** — le plugin qui parle à AWS.
- **Resource** — une ressource déclarée.
- **State** (`terraform.tfstate`) — la correspondance entre le code et le monde réel.
  **Contient des secrets en clair** — d'où sa présence dans `.gitignore`. En équipe,
  on le met dans un backend S3 chiffré avec verrouillage DynamoDB.
- **Plan / Apply / Destroy** — le cycle. `plan` est un *dry-run*, à lire toujours.
- **Drift** — quelqu'un a modifié la ressource à la main ; `plan` le révèle.
- **Modules** — la réutilisation.

Concept lié pour ton axe sécurité : **Checkov / tfsec / Terrascan** analysent le code
Terraform *avant* déploiement. C'est le « shift left » : le CSPM détecte en
production, l'analyse IaC détecte au commit. Comprendre la complémentarité des deux
est un très bon point d'entretien — et une extension naturelle de ton projet.

---

## 4.12 Docker et supply chain

- **Multi-stage** — le stage de build contient les compilateurs et outils ; l'image
  finale n'a que le runtime. Moins de surface d'attaque, image 5 à 10 fois plus
  petite.
- **Non-root** — `USER appuser`. Si un attaquant s'échappe de ton processus, il
  n'est pas root dans le conteneur.
- **Épingler les versions** — `python:3.12-slim` plutôt que `python:latest`, et à
  terme le digest `sha256:`.
- **Scanner l'image** — Trivy détecte les CVE des paquets système et Python.
- **SBOM** — l'inventaire des composants. Après Log4Shell (décembre 2021), la
  question « ai-je log4j quelque part ? » a pris des semaines à répondre dans la
  plupart des entreprises. Le SBOM répond en secondes.
- **Actions GitHub épinglées par SHA** — un tag Git est mutable ; un attaquant qui
  compromet un dépôt d'action peut re-pointer `v3` vers du code malveillant qui
  s'exécutera dans ta CI avec tes secrets. Cette attaque s'est produite plusieurs
  fois en conditions réelles.
