"""Collecteurs : la seule partie du code qui parle a l'API AWS."""

from cspm_lite.collectors.base import COLLECTORS, Collector, collect_all

__all__ = ["COLLECTORS", "Collector", "collect_all"]
