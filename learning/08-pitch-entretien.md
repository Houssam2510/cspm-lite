# 8. Présenter le projet en entretien

## 8.1 La règle d'or

**Ne présente que ce qui existe.** Un recruteur technique creuse toujours. Dire « j'ai
30 checks » alors que tu en as 12 se détecte en une question, et tu perds tout le
crédit du reste — y compris ce que tu as vraiment fait.

La bonne formule quand une partie n'est pas finie : *« la collecte et les checks S3 et
IAM sont en place, le volet réseau est en cours, le labo Terraform est ma prochaine
étape »*. Un projet en cours et lucide vaut mieux qu'un projet fini et menti.

## 8.2 Le pitch de 30 secondes

Pour la question « parlez-moi de vous » ou en salon.

> J'ai construit **cspm-lite**, un scanner de posture de sécurité pour AWS. Il se
> connecte en lecture seule à un compte, inventorie les ressources, et évalue une
> trentaine de contrôles du CIS Benchmark — bucket S3 public, clés IAM trop
> anciennes, ports sensibles exposés, CloudTrail désactivé. La sortie va d'un rapport
> HTML jusqu'à un export vers AWS Security Hub. Ce que j'y ai vraiment appris, c'est
> le risque derrière chaque configuration, pas juste comment appeler l'API.

## 8.3 La version 2 minutes

La structure : **Problème → Approche → Architecture → Validation → Apprentissage**.
C'est la réponse standard à « présentez-moi un projet dont vous êtes fier ».

> **Le problème.** La majorité des brèches cloud ne sont pas des exploits
> sophistiqués, ce sont des erreurs de configuration : Capital One, Accenture,
> Verizon. C'est le modèle de responsabilité partagée — AWS sécurise le cloud, le
> client sécurise dans le cloud. Je voulais comprendre ça de l'intérieur, donc plutôt
> que de lire de la documentation, j'ai reconstruit un outil du type de Prowler.
>
> **L'architecture.** Il y a quatre couches. Une couche d'authentification qui gère
> les profils et l'`AssumeRole`. Des collecteurs qui interrogent S3, IAM, EC2 et
> CloudTrail et produisent un inventaire normalisé. Un moteur de règles où chaque
> check est une fonction décorée, enregistrée dans un registre. Et des reporters :
> JSON, Markdown pour les commentaires de PR, HTML, et ASFF pour Security Hub.
>
> **Le choix dont je suis le plus content**, c'est la séparation stricte entre
> collecte et évaluation. Les collecteurs ne savent rien de la sécurité, les checks ne
> savent rien de boto3. Ça me donne deux choses : je teste tous mes checks sans compte
> AWS, avec des inventaires fabriqués à la main ; et ajouter un contrôle, c'est écrire
> une fonction, pas modifier le moteur.
>
> **La validation.** Pour vérifier que l'outil détecte vraiment quelque chose, j'ai
> écrit un labo Terraform volontairement vulnérable — bucket public, utilisateur avec
> AdministratorAccess, port 22 ouvert sur le monde. Je déploie, je scanne, je vérifie
> que les findings attendus sortent, je détruis.
>
> **Ce que j'en retire.** Je ne détecte pas « un bucket public », je sais ce qu'un
> attaquant en fait. Et j'ai compris qu'un finding isolé ne vaut rien : ce qui compte,
> c'est le chemin entre l'extérieur et la donnée.

Cette dernière phrase est celle qui fait la différence. Garde-la pour la fin.

## 8.4 Le tableau blanc, en 90 secondes

Si on te demande de dessiner. Dessine de gauche à droite, en parlant :

```
  AWS API  ->  auth  ->  collectors  ->  inventaire  ->  checks  ->  findings  ->  reporters
                          (boto3)        normalise      (purs)                    json/md/html/asff
```

Les trois phrases à dire pendant que tu dessines :

1. « Les collecteurs sont la seule partie qui parle à AWS. Pagination, multi-région en
   parallèle, gestion du throttling. »
2. « L'inventaire normalisé est la frontière. Tout ce qui est à droite est du code pur,
   testable sans réseau. »
3. « Les reporters ne connaissent que le modèle de findings. J'en ai quatre, et en
   ajouter un ne touche à rien d'autre. »

Si on te pousse : *« et si je te demande d'ajouter Azure ? »* → « j'écris un
collecteur Azure qui produit le même modèle de `Resource`. Le moteur et les reporters
ne bougent pas. Les checks, eux, sont spécifiques au provider — c'est la limite de
mon abstraction, et je l'assume. »

## 8.5 Les cinq histoires à avoir prêtes

Une histoire = situation, ce que tu as fait, ce que tu as appris. 60 à 90 secondes
chacune. Ce sont elles qu'on retient, pas la liste de technologies.

**1. Le moindre privilège, dérivé empiriquement.**
Mon scanner tournait avec `ReadOnlyAccess`, bien plus large que nécessaire. J'ai
relancé avec une policy vide et ajouté une par une chaque action refusée par un
`AccessDenied`. Résultat : une policy explicite au lieu d'une policy managée fourre-tout,
et la certitude que l'outil ne peut rien faire d'autre que ce qu'il annonce.
→ *Répond à : « comment appliques-tu le moindre privilège concrètement ? »*

**2. Le piège `AuthenticatedUsers`.**
Dans une ACL S3, ce groupe ne veut pas dire « mes utilisateurs » : il désigne
n'importe quel titulaire d'un compte AWS dans le monde. Un bucket avec cette ACL est
public, avec une étape de plus. Je l'ai découvert en écrivant le check, et c'est
typiquement le genre d'erreur qu'un développeur expérimenté commet.
→ *Répond à : « raconte-moi un truc contre-intuitif que tu as appris. »*

**3. L'isolation des pannes.**
Un check qui plante ne doit jamais interrompre les 29 autres. Mon moteur capture
l'exception, produit un finding `NOT_AVAILABLE` avec le message d'erreur, et continue.
Sinon, un bucket supprimé pendant le scan rend l'outil inutilisable en production.
→ *Répond à : « comment penses-tu la robustesse ? »*

**4. IPv6 et le protocole `-1`.**
Sur les security groups, deux erreurs sont quasi systématiques dans les
implémentations amateurs : oublier `::/0`, et mal gérer `IpProtocol: "-1"` qui ouvre
tous les ports sans avoir de champ `FromPort`. J'ai écrit les tests pour ces deux cas
avant le code.
→ *Répond à : « donne-moi un cas limite que tu as géré. »*

**5. Le labo vulnérable.**
J'ai construit en Terraform l'infrastructure que mon outil est censé détecter, puis
j'ai exécuté le scénario d'attaque moi-même. Attaquer et défendre la même
infrastructure change la façon d'écrire une détection.
→ *Répond à : « comment sais-tu que ton outil marche ? »*

## 8.6 Les questions de relance et comment y répondre

**« En quoi c'est différent de Prowler ? »**
Ce n'est pas différent, et c'était volontaire. Prowler est mature, je ne prétends pas
faire mieux. Mon objectif était de reconstruire l'architecture pour comprendre les
décisions qu'elle contient. J'ai d'ailleurs lu leur code et j'ai fait certains choix
différemment — par exemple, eux chargent les checks dynamiquement depuis le système de
fichiers, moi j'utilise un registre explicite, ce qui est plus simple à tracer mais
moins souple.

**« Quelles sont les limites de ton outil ? »**
La meilleure question qu'on puisse te poser. Réponse honnête et structurée :
- pas d'**analyse de chemin d'attaque** — je sors des findings isolés, pas le chemin
  entre une entrée exposée et une donnée sensible ;
- pas de **contexte métier**, donc pas de vraie priorisation : un bucket public de
  logs publics est un faux positif que je n'ai aucun moyen de distinguer ;
- c'est un **instantané**, pas de la détection temps réel — le volet CloudTrail
  serait la suite logique ;
- **un seul provider**, et mes checks ne sont pas transposables tels quels.

**« Combien de temps ça t'a pris ? »**
Ne minimise pas. « Environ 80 heures sur trois mois, en parallèle des cours. » Un
chiffre honnête montre que tu sais estimer.

**« Pourquoi des threads et pas asyncio ? »**
Le scan est *I/O bound* : on attend l'API AWS. Les threads suffisent, le GIL n'est pas
un problème puisqu'on attend du réseau. `asyncio` aurait demandé `aioboto3` et
compliqué le code pour un gain nul à cette échelle — 17 régions, pas 10 000 requêtes.

**« Comment testes-tu du code qui appelle AWS ? »**
Deux niveaux. Les checks sont des fonctions pures, je leur injecte des inventaires
fabriqués — c'est instantané et ça couvre tous les cas limites. Les collecteurs, je
les teste avec `moto`, qui simule les services AWS en mémoire. Le point important,
c'est que mon architecture rend le premier niveau possible : c'est le retour sur
investissement de la séparation collecte/évaluation.

**« Qu'est-ce que tu ferais différemment ? »**
J'aurais figé le modèle de `Finding` plus tôt : je l'ai fait évoluer trois fois et
chaque changement m'a coûté du travail dans les quatre reporters. Et j'aurais écrit le
labo Terraform avant les checks plutôt qu'après — j'aurais validé au fur et à mesure
au lieu de découvrir des écarts à la fin.

**« Tu l'utiliserais en production ? »**
Non, pas tel quel. Il n'a pas la couverture de Prowler, pas de gestion multi-comptes
via AWS Organizations, et je n'ai pas de retour terrain sur les faux positifs. En
revanche, il m'a donné les bases pour utiliser et comprendre un vrai CSPM, y compris
pour savoir quoi contester dans ses résultats.

## 8.7 Adapter selon l'interlocuteur

| Interlocuteur | Ce qu'il veut entendre | Durée | À éviter |
|---|---|---|---|
| **RH** | Le problème résolu, en français courant, et un chiffre | 45 s | Tout jargon technique |
| **Ingénieur sécurité** | Les contrôles, le risque réel, ton scénario d'attaque | 3-5 min | Parler surtout de Python |
| **Lead dev / architecte** | La séparation des couches, la testabilité, les compromis | 3-5 min | Parler surtout de sécurité |
| **Manager / CTO** | Pourquoi tu l'as fait, ce que tu mesures, tes limites | 2 min | Les détails d'implémentation |

Pour le RH, la version courte : *« un outil qui vérifie automatiquement qu'un compte
cloud est configuré sans faille de sécurité, en s'appuyant sur un référentiel
international. C'est le type d'outil que les entreprises utilisent pour éviter les
fuites de données qu'on voit dans la presse. »*

## 8.8 Les pièges à éviter

1. **« C'est juste un projet perso »** — ne dévalorise jamais ton propre travail en
   ouverture. Dis ce que c'est, pas ce que ce n'est pas.
2. **Réciter.** Un pitch appris par cœur s'entend et bloque le dialogue. Retiens la
   *structure* (problème → architecture → validation → apprentissage), pas les phrases.
3. **Le name-dropping.** Énumérer « Python, boto3, Terraform, Docker, GitHub Actions,
   pytest, moto » ne dit rien. Une décision technique expliquée vaut dix technologies
   citées.
4. **Ne pas savoir dire ce qui ne marche pas.** Un candidat sans limites à énoncer
   n'a pas assez creusé. Prépare tes limites autant que tes réussites.
5. **Le nombre de checks comme argument.** Personne n'est impressionné par 30 checks.
   Un check expliqué en profondeur, avec l'incident réel qu'il aurait évité, oui.
6. **Oublier la question retour.** Termine par une question : *« vous utilisez quoi
   pour la posture cloud, et sur combien de comptes ? »* Tu passes de candidat
   interrogé à interlocuteur.

## 8.9 La veille de l'entretien

- Relis ton **carnet de preuves** (section 7.7), pas ton code.
- Redis le pitch de 2 minutes **à voix haute**, une fois, chronométré.
- Redessine l'architecture sur une feuille, sans regarder.
- Prépare **une** anecdote parmi les cinq, celle qui colle le mieux au poste.
- Vérifie que ton dépôt est accessible, que le README s'affiche bien, et que le lien
  vers le rapport HTML d'exemple fonctionne.
- Prépare tes deux questions à leur poser.
