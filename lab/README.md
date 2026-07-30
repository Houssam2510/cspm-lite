# Labo AWS volontairement vulnérable

> **Avertissement.** Ce code crée de **vraies ressources non sécurisées** dans votre
> compte AWS : un bucket S3 public, un utilisateur avec `AdministratorAccess`, des
> ports ouverts sur Internet.

## Avant de commencer

1. **Compte AWS dédié.** Jamais un compte contenant des données réelles.
2. **Budget avec alerte**, posé *avant* le premier `apply` :
   ```bash
   aws budgets create-budget --account-id <ID> --budget \
     '{"BudgetName":"cspm-lab","BudgetLimit":{"Amount":"5","Unit":"USD"},"TimeUnit":"MONTHLY","BudgetType":"COST"}'
   ```
   Ou via la console : Billing → Budgets → Create budget.
3. **Vérifier `.gitignore`.** `*.tfstate` et `*.tfvars` sont exclus : le state contient
   des données sensibles en clair.

## Cycle de vie

```bash
cd lab
terraform init
terraform plan -var="owner=$USER"      # toujours lire le plan
terraform apply -var="owner=$USER"

# Scanner le labo avec le rôle en lecture seule créé par le labo
cspm-lite scan \
  --role-arn "$(terraform output -raw role_scanner_arn)" \
  --external-id cspm-lite-lab \
  --region eu-west-3 \
  --format html -o ../rapport-lab.html

# IMPÉRATIF en fin de session
terraform destroy -var="owner=$USER"
```

## Coût

Par défaut, **aucune ressource facturée** : buckets vides, utilisateur IAM, security
group. Coût attendu : 0 $.

`-var="enable_compute=true"` ajoute une instance `t3.micro` (~0,01 $/h) pour tester
les contrôles IMDSv2 et EBS. À détruire immédiatement après.

## Ce que le scan doit détecter

Si `cspm-lite` ne lève pas ces findings, c'est l'outil qui a un bug, pas
l'infrastructure :

| Check | Ressource | Attendu |
|---|---|---|
| S3-001 | bucket `*-public-*` | FAIL — Block Public Access désactivé |
| S3-002 | bucket `*-public-*` | FAIL — policy `Principal: "*"` |
| S3-003 | bucket `*-public-*` | FAIL — pas de chiffrement |
| S3-004 | bucket `*-public-*` | FAIL — pas de versioning |
| S3-006 | bucket `*-public-*` | FAIL — pas de condition TLS |
| S3-001..006 | bucket `*-sain-*` | PASS — le témoin |
| IAM-007 | `*-deployer` | FAIL — `AdministratorAccess` attaché directement |
| IAM-008 | `*-legacy-full-access` | FAIL — `Action: "*"` sur `Resource: "*"` |
| NET-001 | `*-expose` | FAIL — 22 (SSH) et 3306 (MySQL) |
| NET-003 | `default` | dépend du compte |
| NET-004 | VPC par défaut | FAIL — pas de flow logs |
| NET-006 | instance | FAIL si `enable_compute=true` |

Le bucket témoin `*-sain-*` est important : un scanner qui met tout en FAIL n'est pas
plus utile qu'un scanner qui ne détecte rien. Il valide l'absence de faux positifs.

## Le rôle scanner

Le labo crée `<prefix>-scanner`, un rôle portant la policy managée `SecurityAudit` et
exigeant un `ExternalId`. C'est le moindre privilège appliqué à l'outil lui-même :
`cspm-lite` n'a jamais besoin d'écrire, et l'`ExternalId` protège du *confused
deputy*.

## Aller plus loin

Une fois le labo en place, exécutez vous-même le chemin d'attaque plutôt que de vous
contenter de le détecter : récupérez la clé du `deployer`, listez le bucket public,
assumez un rôle. Attaquer et défendre la même infrastructure change la façon d'écrire
une détection — et c'est votre meilleure anecdote d'entretien.
