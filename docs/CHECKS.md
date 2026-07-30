# Catalogue des contrôles

Généré par `cspm-lite list-checks --format markdown`. Ne pas éditer à la main.

| ID | Service | Severite | CIS | Titre |
| --- | --- | --- | --- | --- |
| IAM-001 | iam | CRITICAL | 1.4 | Le compte root n'a pas de cle d'acces |
| IAM-002 | iam | CRITICAL | 1.5 | MFA active sur le compte root |
| IAM-003 | iam | HIGH | 1.10 | MFA active pour tous les utilisateurs a acces console |
| IAM-004 | iam | HIGH | 1.14 | Aucune cle d'acces de plus de 90 jours |
| IAM-005 | iam | MEDIUM | 1.12 | Aucune credential inutilisee depuis 45 jours |
| IAM-006 | iam | MEDIUM | 1.8 | Politique de mot de passe conforme |
| IAM-007 | iam | HIGH | 1.16 | Aucun utilisateur avec AdministratorAccess attache directement |
| IAM-008 | iam | HIGH | 1.16 | Aucune policy client n'accorde Action '*' sur Resource '*' |
| LOG-001 | cloudtrail | CRITICAL | 3.1 | Au moins un trail CloudTrail multi-region est actif |
| LOG-002 | cloudtrail | HIGH | 3.2 | Validation d'integrite des fichiers de log activee |
| LOG-003 | cloudtrail | MEDIUM | 3.5 | Logs CloudTrail chiffres avec KMS |
| LOG-004 | cloudtrail | MEDIUM | 3.4 | Trail integre a CloudWatch Logs |
| LOG-005 | cloudtrail | HIGH | 3.1 | Le trail est effectivement en train de journaliser |
| NET-001 | ec2 | CRITICAL | 5.2 | Port sensible expose sur Internet |
| NET-002 | ec2 | CRITICAL | 5.2 | Aucun security group n'ouvre tous les ports au monde |
| NET-003 | ec2 | MEDIUM | 5.4 | Le security group par defaut n'autorise aucun trafic |
| NET-004 | ec2 | MEDIUM | 3.7 | VPC Flow Logs actives |
| NET-005 | ec2 | MEDIUM | 2.2.1 | Volumes EBS chiffres |
| NET-006 | ec2 | HIGH | 5.6 | IMDSv2 obligatoire sur les instances EC2 |
| S3-001 | s3 | HIGH | 2.1.4 | Block Public Access active sur le bucket |
| S3-002 | s3 | CRITICAL | 2.1.4 | Bucket S3 accessible publiquement |
| S3-003 | s3 | MEDIUM | 2.1.1 | Chiffrement par defaut active |
| S3-004 | s3 | MEDIUM | — | Versioning active |
| S3-005 | s3 | LOW | — | Journalisation des acces activee |
| S3-006 | s3 | MEDIUM | 2.1.2 | Policy imposant le chiffrement en transit (TLS) |
