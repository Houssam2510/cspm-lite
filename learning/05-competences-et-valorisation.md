# 5. Compétences acquises et valorisation

## 5.1 Ce que ce projet met réellement sur ton CV

| Compétence | Où tu l'acquiers | Comment un recruteur la lit |
|---|---|---|
| Sécurité cloud AWS | Phase 3 | « Connaît le CIS Benchmark, pas juste le nom d'AWS » |
| IAM avancé (STS, AssumeRole, policies) | Phases 2-3 | Compétence rare chez un junior |
| boto3 / API AWS en production | Phase 2 | Pagination, throttling, multi-région |
| Terraform / IaC | Phase 6 | Compétence la plus demandée du marché cloud |
| Python d'ingénierie (typé, testé, packagé) | Phases 0-1-7 | Distingue « sait coder » de « sait livrer » |
| Architecture logicielle (registry, séparation des couches) | Phase 1 | Sujet de discussion technique en entretien |
| Tests avec mocks cloud (moto) | Phase 7 | Très peu d'étudiants savent le faire |
| CI/CD et DevSecOps | Phase 8 | Trivy, SBOM, actions épinglées |
| Sécurité de la supply chain | Phase 8 | Sujet chaud post-Log4Shell / xz-utils |
| Pipeline data et métriques | Phase 9 | Ton différenciateur data |
| Conformité et GRC | Phase 3 | Vocabulaire des équipes sécurité |

## 5.2 Formulations pour ton CV

À adapter, jamais copier tel quel — et **ne mets rien que tu ne saches défendre**.

> **cspm-lite — Scanner de posture de sécurité cloud AWS** (Python, boto3, Terraform, Docker)
> Outil d'audit automatisé implémentant 30+ contrôles du CIS AWS Foundations
> Benchmark (IAM, S3, réseau, logging). Architecture en couches collecte/évaluation
> avec registre de règles extensible ; scan multi-région parallélisé ; rapports
> JSON/HTML/Markdown et export ASFF vers AWS Security Hub. Labo Terraform
> volontairement vulnérable pour la validation ; 85 % de couverture de tests avec
> moto ; CI GitHub Actions avec lint, typage, scan de conteneur Trivy et SBOM.

Version courte pour LinkedIn :

> J'ai construit cspm-lite, un CSPM open source pour AWS : 30+ checks CIS,
> collecte multi-région parallélisée, export Security Hub, labo Terraform vulnérable
> et CI DevSecOps complète. Le but n'était pas de refaire Prowler mais de comprendre
> de l'intérieur pourquoi les comptes cloud se font compromettre.

## 5.3 Les questions d'entretien que ce projet te prépare à gérer

Entraîne-toi à répondre en 2 minutes maximum à chacune :

**Cloud / sécurité**
1. Qu'est-ce que le modèle de responsabilité partagée ?
2. Comment un bucket S3 devient-il public ? Cite les quatre mécanismes.
3. Différence entre un rôle et un utilisateur IAM ? Lequel préfères-tu et pourquoi ?
4. Comment un outil tiers accède-t-il à un compte AWS client en sécurité ?
   (AssumeRole + ExternalId, et pourquoi l'ExternalId existe)
5. Raconte-moi une brèche cloud réelle et sa cause technique. (Capital One)
6. Comment détectes-tu qu'un attaquant a effacé ses traces ? (validation d'intégrité
   CloudTrail)
7. Security group vs NACL ?
8. Qu'est-ce qu'IMDSv2 résout ?
9. Comment donnerais-tu à ton scanner le droit de lire un compte sans le compromettre ?

**Génie logiciel**
10. Explique l'architecture de ton projet et pourquoi tu as séparé collecte et
    évaluation.
11. Comment testes-tu du code qui appelle AWS, sans compte AWS ?
12. Ton scan est lent : comment l'optimises-tu ? (threads car I/O bound, pagination,
    filtrage des régions actives)
13. Un check plante en production. Que se passe-t-il ? (isolation des pannes)

**DevOps**
14. Pourquoi un Dockerfile multi-stage ?
15. Pourquoi épingler les actions GitHub par SHA ?
16. Qu'est-ce qu'un SBOM et à quoi ça sert ?

**Data**
17. Comment mesures-tu si la posture de sécurité s'améliore ? (score dans le temps,
    MTTR, taux de récidive — pas le nombre brut de findings)
18. Comment modélises-tu l'historique des findings ? (snapshot d'état vs événements)

## 5.4 Certifications cohérentes avec ce projet

Le projet te prépare directement à plusieurs certifications. Ordre recommandé :

1. **AWS Certified Cloud Practitioner** (facultatif si tu es déjà à l'aise) — 100 $.
2. **AWS Certified Solutions Architect – Associate** — la plus reconnue, 150 $. Le
   projet couvre déjà IAM, S3, VPC, CloudTrail.
3. **AWS Certified Security – Specialty** — 300 $. Ton projet en couvre facilement
   30 à 40 % du programme. C'est la certification la plus alignée.
4. **HashiCorp Terraform Associate** — 70 $, très accessible après la phase 6.
5. Côté sécurité générale : **CompTIA Security+** si tu vises un premier poste
   généraliste, ou le parcours **TryHackMe / HackTheBox** pour l'offensif.

Note importante : les certifications sans projet sont creuses, et le projet sans
certification passe parfois les filtres RH difficilement. La combinaison des deux est
ce qui fonctionne.

## 5.5 Extensions possibles (après la v1)

Quand le projet est fini, ces extensions le font passer d'un bon projet étudiant à un
portfolio remarquable :

- **Multi-cloud** — ajouter un collecteur Azure ou GCP. Prouve que ton architecture
  était bonne : si ajouter Azure ne demande pas de réécrire le moteur, ton design
  tenait.
- **Analyse IaC** — scanner les fichiers Terraform avant déploiement (le « shift
  left »), en réutilisant tes checks.
- **Remédiation automatique** — un mode `--fix` qui corrige les findings à faible
  risque (activer Block Public Access, par exemple), avec confirmation obligatoire.
  Attention : c'est là que se cachent les incidents ; exige un `--yes` explicite et
  un mode `--dry-run` par défaut.
- **Attack path analysis** — le sujet le plus intéressant intellectuellement :
  construire un graphe des relations IAM (qui peut assumer quel rôle, qui peut
  atteindre quelle donnée) et chercher les chemins d'escalade de privilèges. C'est ce
  que font Wiz et Cartography. Un graphe `networkx` suffit pour une v1.
- **Intégration Slack / ticketing** — un finding CRITICAL crée une issue GitHub ou un
  message Slack.
- **Mode serveur** — une API FastAPI + un scan planifié, pour un suivi continu.

## 5.6 Le plan de travail réaliste

Si tu es étudiant à temps plein, vise **6 à 8 heures par semaine sur 10 à 12
semaines**.

| Semaines | Objectif | Livrable visible |
|---|---|---|
| 1 | Phases 0 et 1 | Paquet installable, moteur fonctionnel |
| 2-3 | Phase 2 | `cspm-lite scan` liste tes ressources réelles |
| 4-6 | Phase 3 | 25+ checks, le cœur du projet |
| 7 | Phases 4 et 5 | Rapport HTML présentable, CLI complète |
| 8 | Phase 7 | Tests à 80 %, badge de couverture |
| 9 | Phase 6 | Labo Terraform validant les checks |
| 10 | Phase 8 | CI verte, image Docker publiée |
| 11-12 | Phases 9 et 10 | Historique, article, release v1.0.0 |

**Règle anti-abandon** : un commit par session de travail, même minuscule. Le graphe
de contributions GitHub qui se remplit est un moteur psychologique réel, et un
recruteur regarde la régularité autant que le contenu.

**Règle anti-perfectionnisme** : ne repars pas en arrière pour « améliorer » une
phase terminée avant d'avoir atteint la phase 10. Un projet fini à 80 % vaut infiniment
plus que trois phases parfaites et un projet mort.
