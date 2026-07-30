# ADR-004 — Le score de posture est pondéré par sévérité

**Statut** : accepté · **Date** : 2026-07-30

## Contexte

Il faut un chiffre unique pour répondre à « est-ce que ça s'améliore ». Deux
candidats simples :

- **taux de conformité** = `PASS / (PASS + FAIL)`. Défaut rédhibitoire : réussir dix
  contrôles informatifs compense un bucket public. Le chiffre récompense le volume,
  pas la sécurité.
- **nombre de findings**. Défaut : dépend surtout du périmètre scanné. Ajouter une
  région fait « empirer » la posture sans qu'aucune configuration n'ait changé.

## Décision

`score = 100 × Σ(poids des PASS) / Σ(poids des PASS et FAIL)`

avec `CRITICAL=10, HIGH=5, MEDIUM=3, LOW=1, INFORMATIONAL=0`.

Les statuts `NOT_AVAILABLE` et `WARNING` sont exclus du calcul, ainsi que les
findings explicitement supprimés (voir ADR-005). Un dénominateur nul renvoie 100.

## Conséquences

**Positives.** Un seul `CRITICAL` en échec fait chuter le score de façon visible.
Le chiffre est comparable d'un scan à l'autre sur un périmètre stable, ce qui rend la
courbe de tendance (`cspm-lite history`) lisible.

**Négatives.** Les poids sont arbitraires — défendables, mais arbitraires. Le score
reste comparable **dans le temps sur un même compte**, pas entre deux comptes de
tailles différentes. Il ne remplace pas la lecture des findings critiques.

**Ce qu'il ne mesure pas.** Le score dit où on en est, pas si l'équipe s'améliore.
C'est le rôle du MTTR et du taux de récidive (`history.py`), qui mesurent le
*processus* et non l'*inventaire*.
