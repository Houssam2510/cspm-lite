# Exercice 5 — Security groups exposés sur Internet

**Phase du projet** : 3 · **Durée visée** : 2 h · **Difficulté** : 4/5

## Contexte

Un port 22 ouvert sur `0.0.0.0/0` est scanné et attaqué en force brute dans les
minutes qui suivent son ouverture — ce n'est pas une image, c'est mesurable. Un port
3306 ouvert, c'est une base de données MySQL offerte à Internet.

Cet exercice est celui où la plupart des implémentations amateurs se trompent, pour
trois raisons : **IPv6 oublié**, **protocole `-1` mal géré**, et **plages de ports**
traitées comme des valeurs uniques. Les trois sont testés ici.

## Le format d'entrée

Un security group, tel que renvoyé par `describe_security_groups` :

```python
{
    "GroupId": "sg-0a1b2c",
    "GroupName": "web",
    "region": "eu-west-3",
    "IpPermissions": [
        {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            "Ipv6Ranges": [],
            "UserIdGroupPairs": [],
        }
    ],
}
```

Trois subtilités du format AWS :

1. `IpProtocol` vaut `"-1"` pour **tous les protocoles**. Dans ce cas, `FromPort` et
   `ToPort` sont **absents** — et tous les ports sont ouverts.
2. `FromPort`/`ToPort` décrivent une **plage**. `20`–`25` inclut le port 22.
3. `UserIdGroupPairs` autorise un **autre security group**, pas une plage IP. Ce
   n'est jamais une exposition Internet — c'est même la bonne pratique.

## À implémenter dans `exercice.py`

### 1. `is_world_open(cidr) -> bool`

`True` pour `"0.0.0.0/0"` et `"::/0"`, `False` sinon. Utilise le module `ipaddress`,
pas une comparaison de chaînes : `"0.0.0.0/0"` et `"0.0.0.0/00"` sont le même réseau.

### 2. `is_overly_broad(cidr) -> bool`

`True` si le réseau contient **strictement plus de 65 536 adresses**, c'est-à-dire
plus large qu'un `/16` en IPv4. Sert à repérer les `10.0.0.0/8` ou les plages
d'opérateur ouvertes « pour dépanner ».

### 3. `permission_covers_port(perm, port) -> bool`

- `IpProtocol` valant `"-1"` → `True` pour **tous** les ports, même si `FromPort` et
  `ToPort` sont absents ;
- `IpProtocol` valant `"tcp"` ou `"6"` → `True` si `FromPort <= port <= ToPort` ;
- tout autre protocole (`udp`, `icmp`, `17`…) → `False`.

### 4. `permission_world_open(perm) -> bool`

`True` si au moins une entrée de `IpRanges` (clé `CidrIp`) **ou** de `Ipv6Ranges`
(clé `CidrIpv6`) est ouverte au monde. `UserIdGroupPairs` et `PrefixListIds` ne
comptent pas.

### 5. `open_sensitive_ports(sg) -> set[int]`

L'ensemble des ports de `PORTS_SENSIBLES` accessibles depuis Internet — c'est-à-dire
couverts par une permission qui est à la fois ouverte au monde et couvrante pour ce
port.

### 6. `check_security_groups(sgs) -> list[Finding]`

Un `Finding` par security group, dans l'ordre reçu :

| Champ | Valeur |
|---|---|
| `check_id` | `"NET-001"` |
| `title` | `"Port sensible expose sur Internet"` |
| `severity` | `Severity.CRITICAL` |
| `status` | `FAIL` si au moins un port sensible est exposé, sinon `PASS` |
| `resource.id` | le `GroupId` |
| `resource.type` | `"AWS::EC2::SecurityGroup"` |
| `resource.name` | le `GroupName` |
| `resource.region` | la clé `region` du SG, `""` si absente |
| `details` | les ports triés, format `"22 (SSH), 3306 (MySQL)"`, chaîne vide si aucun |
| `remediation` | une phrase non vide |

## Vérifier ton travail

```bash
cd learning/exercices/ex5-security-groups
python3 -m unittest discover -v
```

## Auto-évaluation

- Pourquoi UDP 3306 n'est-il pas signalé alors que TCP 3306 l'est ?
- Un SG qui autorise `0.0.0.0/0` sur le port 443 : faut-il le signaler ? Où mets-tu
  la limite entre « exposé » et « exposé à tort » ?
- Ton check regarde le security group isolément. Qu'est-ce qui manque pour savoir si
  le port est **réellement** joignable depuis Internet ? (pense à la table de
  routage, à la NACL, à l'IP publique, à l'état de l'instance)
- Quelle est l'alternative moderne à l'ouverture du port 22 ?
