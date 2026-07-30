# ADR-001 — Séparer strictement collecte et évaluation

**Statut** : accepté · **Date** : 2026-07-30

## Contexte

Un scanner de posture doit interroger l'API AWS puis évaluer des règles de sécurité
sur ce qu'il a trouvé. La solution naturelle — chaque check appelle lui-même les API
dont il a besoin — pose trois problèmes :

1. **Impossible à tester sans compte AWS.** Chaque test devient un test
   d'intégration, lent et coûteux.
2. **Appels redondants.** Dix checks S3 déclencheraient dix `ListBuckets`.
3. **Couplage.** Un changement d'API AWS oblige à modifier tous les checks concernés.

## Décision

`Inventory` est une frontière étanche.

- Les **collecteurs** (`collectors/`) sont les seuls, avec `auth.py`, à importer
  `boto3`. Ils produisent des `Resource` normalisées et ne connaissent aucune règle
  de sécurité.
- Les **checks** (`engine/checks/`) sont des fonctions pures
  `(Inventory) -> list[Finding]`. Ils n'importent jamais `boto3`.

## Conséquences

**Positives.** Les 25 checks sont testés en 0,05 s sans réseau ni mock, avec des
inventaires fabriqués à la main qui couvrent tous les cas limites. Ajouter un
contrôle est une fonction décorée. Ajouter un provider (Azure, GCP) demande un
collecteur, pas une réécriture du moteur.

**Négatives.** L'inventaire est chargé intégralement en mémoire : sur un compte de
plusieurs dizaines de milliers de ressources, il faudrait passer à un traitement en
flux. Un check ne peut pas déclencher un appel API supplémentaire au vol — s'il a
besoin d'une donnée, il faut l'ajouter au collecteur.

**Coût assumé.** Les collecteurs récupèrent parfois des données qu'aucun check
n'utilise. C'est le prix de la découplage, et il est faible.
