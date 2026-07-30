"""Configuration de la campagne de tests.

Point de securite non negociable : des credentials AWS factices sont injectees dans
l'environnement **avant** tout import de boto3. Si un test venait a echapper au mock
moto, il taperait sinon sur le vrai compte AWS configure sur la machine. C'est un
piege classique et couteux.

Ce fichier ne contient volontairement aucune fixture pytest : les tests sont ecrits
en `unittest.TestCase`, ce qui permet de les lancer aussi bien avec `pytest` qu'avec
`python -m unittest`, sans installer quoi que ce soit.
"""

from __future__ import annotations

import os

os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
os.environ.setdefault("AWS_SECURITY_TOKEN", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
