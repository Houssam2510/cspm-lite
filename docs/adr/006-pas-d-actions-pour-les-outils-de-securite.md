# ADR-006 — Lancer Trivy et Syft depuis leur image, pas via leur action GitHub

**Statut** : accepté · **Date** : 2026-07-30 · **Origine** : échec de CI réel

## Contexte

La CI épinglait toutes ses actions par SHA plutôt que par tag, précisément parce
qu'un tag est mutable : un attaquant qui compromet le dépôt d'une action peut faire
pointer `v3` vers du code malveillant, exécuté dans notre pipeline avec nos secrets.

Le premier passage de la CI a échoué au job Docker, en 3 secondes, avant la moindre
étape :

```
##[error]Unable to resolve action `aquasecurity/setup-trivy@v0.2.2`,
unable to find version `v0.2.2`
```

`aquasecurity/trivy-action`, que nous avions correctement épinglée par SHA, appelle
en interne une **autre action référencée par tag**. Ce tag a disparu en amont, et
notre pipeline est tombé — sans qu'aucune ligne de notre code n'ait changé.

## La leçon

**L'épinglage par SHA ne protège qu'à la profondeur où on l'applique.** Une action
épinglée qui résout elle-même une sous-action par tag mutable annule la garantie :
la surface d'attaque réelle inclut tout l'arbre transitif, pas seulement le premier
niveau.

C'est exactement le mécanisme des compromissions de chaîne d'approvisionnement
réelles — `event-stream`, `ua-parser-js`, `tj-actions/changed-files` en 2025 : la
victime n'utilisait pas directement le composant compromis.

Et l'incident illustre un second point : la **disponibilité** est aussi un enjeu de
supply chain. Ici le tag a simplement disparu ; le résultat est le même qu'un déni de
service sur notre pipeline.

## Décision

Ne pas utiliser d'action GitHub pour les outils de sécurité. Les lancer depuis leur
**image officielle épinglée par version**, dans une étape `run` :

```yaml
env:
  TRIVY_IMAGE: aquasec/trivy:0.72.0
  SYFT_IMAGE: anchore/syft:v1.50.0
```

Aucune sous-action, donc aucune dépendance transitive mutable. Les actions
maintenues par GitHub lui-même (`checkout`, `setup-python`, `upload-artifact`)
restent utilisées, épinglées par SHA.

## Conséquences

**Positives.** L'arbre de dépendances de la CI est entièrement connu et figé. Le
comportement est identique en local et en CI — on peut reproduire le scan Trivy sur
sa machine avec la même commande. Moins de magie, plus de lisibilité.

**Négatives.** Il faut écrire soi-même les options de ligne de commande que l'action
enveloppait, et suivre manuellement les montées de version. Dependabot met à jour les
images Docker, mais pas une variable `env` : c'est un point de dette assumé, à
revoir si le nombre d'outils augmente.

**Alternative écartée.** Épingler l'image par digest `sha256:` plutôt que par
version. Plus strict, mais illisible et pénible à mettre à jour à la main pour un
gain marginal ici — les images officielles Trivy et Syft ne sont pas republiées sous
la même version.
