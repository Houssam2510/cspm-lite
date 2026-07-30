# syntax=docker/dockerfile:1
#
# Image multi-stage.
#
# - Le stage `builder` contient les outils de compilation et le cache pip ;
#   l'image finale n'embarque que le runtime, ce qui reduit la taille et surtout
#   la surface d'attaque (pas de compilateur disponible pour un attaquant).
# - L'image tourne en utilisateur non-root : une evasion du processus ne donne pas
#   root dans le conteneur.
# - Les versions de base sont epinglees : `latest` rendrait les builds non
#   reproductibles et exposerait a une image amont modifiee.

FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip setuptools \
    && /opt/venv/bin/pip install . \
    # Le runtime n'a pas besoin d'un gestionnaire de paquets. Le retirer a deux
    # effets : ses vulnerabilites (pip embarque setuptools et des dependances
    # vendorisees comme msgpack) disparaissent de l'image, et un attaquant qui
    # obtiendrait l'execution de code n'y trouve aucun moyen d'installer du sien.
    # C'est un scan Trivy en CI qui a rendu ce probleme visible.
    && /opt/venv/bin/pip uninstall -y pip setuptools wheel || true \
    && rm -rf /opt/venv/lib/python*/site-packages/pip* \
              /opt/venv/lib/python*/site-packages/setuptools* \
              /opt/venv/lib/python*/site-packages/pkg_resources \
              /opt/venv/lib/python*/site-packages/wheel* \
              /opt/venv/bin/pip*


FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="cspm-lite" \
      org.opencontainers.image.description="Scanner de posture de securite cloud pour AWS" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.source="https://github.com/Houssam2510/cspm-lite"

# Utilisateur non privilegie, sans shell de connexion.
RUN groupadd --system --gid 10001 cspm \
    && useradd --system --uid 10001 --gid cspm --no-create-home --shell /usr/sbin/nologin cspm

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER cspm
WORKDIR /work

# Verifie que le binaire repond ; utile en orchestration.
HEALTHCHECK --interval=1m --timeout=10s --retries=2 \
    CMD ["cspm-lite", "--version"]

ENTRYPOINT ["cspm-lite"]
CMD ["--help"]
