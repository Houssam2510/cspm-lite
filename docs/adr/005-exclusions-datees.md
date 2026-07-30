# ADR-005 — Toute exclusion exige une justification et une date d'expiration

**Statut** : accepté · **Date** : 2026-07-30

## Contexte

Tout outil de sécurité a besoin d'exclusions : un bucket de contenus publics est
public par conception, la journalisation d'accès y est superflue. Sans mécanisme
d'exclusion, l'équipe apprend à ignorer le rapport — et c'est la mort de l'outil.

Mais une exclusion est une **acceptation de risque**. Dans la plupart des outils,
elle est une ligne de configuration sans contexte, ajoutée un mardi par quelqu'un qui
a quitté l'entreprise depuis, et que plus personne n'ose retirer.

## Décision

Dans `.cspm.toml`, chaque exclusion **doit** porter `reason` et `expires_at`.
L'absence de l'un des deux est une erreur fatale de configuration, pas un
avertissement.

Passée la date, l'exclusion cesse de s'appliquer : le finding redevient bloquant, et
un avertissement rappelle l'exclusion périmée. Une exclusion qui ne correspond à
aucun finding est également signalée.

Un finding exclu n'est pas supprimé du rapport : il reste visible avec sa
justification, mais sort du score et du code de sortie.

## Conséquences

**Positives.** La dette de sécurité devient visible et datée. Le rapport reste
honnête — on voit ce qui a été accepté, et pourquoi. La réévaluation périodique est
imposée par l'outil plutôt que par la discipline.

**Négatives.** Plus contraignant que la concurrence : on ne peut pas « faire taire »
un check en une ligne. Une équipe pressée le vivra comme une friction. C'est
délibéré : la friction est ici le produit, pas un défaut.

**Alternative écartée.** Un champ `permanent = true` pour les exclusions
structurelles. Rejeté : « permanent » est exactement ce qu'on cherche à empêcher. Une
exclusion structurelle se renouvelle tous les ans, ce qui force à la reconfirmer.
