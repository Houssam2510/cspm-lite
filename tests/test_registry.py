"""Tests du registre : enregistrement, filtres, et isolation des pannes."""

from __future__ import annotations

import unittest

from cspm_lite.engine.models import Finding, Inventory, Resource, Severity, Status
from cspm_lite.engine.registry import (
    REGISTRY,
    check,
    clear_registry,
    get_checks,
    load_all_checks,
    make_finding,
    run_checks,
)


def f(check_id="A"):
    return Finding(
        check_id=check_id,
        title="t",
        severity=Severity.LOW,
        status=Status.PASS,
        resource=Resource(id="r"),
    )


class BaseRegistre(unittest.TestCase):
    """Chaque test repart d'un registre vide, puis le restaure a la fin."""

    def setUp(self):
        self._sauvegarde = dict(REGISTRY)
        clear_registry()

    def tearDown(self):
        clear_registry()
        REGISTRY.update(self._sauvegarde)


class TestEnregistrement(BaseRegistre):
    def test_metadonnees(self):
        @check(id="S3-X", title="T", severity=Severity.HIGH, service="s3", cis="2.1.4")
        def c(inv):
            return []

        meta = get_checks()[0]
        self.assertEqual((meta.id, meta.title, meta.service, meta.cis), ("S3-X", "T", "s3", "2.1.4"))
        self.assertEqual(meta.severity, Severity.HIGH)

    def test_fonction_renvoyee_intacte(self):
        @check(id="A", title="t", severity=Severity.LOW, service="s3")
        def c(inv):
            return [f()]

        self.assertEqual(len(c(Inventory())), 1, "le check doit rester appelable directement")

    def test_id_duplique_rejete(self):
        @check(id="DUP", title="t", severity=Severity.LOW, service="s3")
        def c1(inv):
            return []

        with self.assertRaises(ValueError):

            @check(id="DUP", title="t", severity=Severity.LOW, service="iam")
            def c2(inv):
                return []

    def test_ordre_preserve(self):
        for i in ("A", "B", "C"):

            @check(id=i, title=i, severity=Severity.LOW, service="s3")
            def c(inv):
                return []

        self.assertEqual([m.id for m in get_checks()], ["A", "B", "C"])


class TestFiltres(BaseRegistre):
    def setUp(self):
        super().setUp()
        for cid, svc, sev in [
            ("S3-1", "s3", Severity.HIGH),
            ("S3-2", "S3", Severity.LOW),
            ("IAM-1", "iam", Severity.CRITICAL),
        ]:

            @check(id=cid, title=cid, severity=sev, service=svc)
            def c(inv):
                return []

    def test_service_insensible_casse(self):
        self.assertEqual(sorted(m.id for m in get_checks(service="s3")), ["S3-1", "S3-2"])

    def test_severite_minimale_inclusive(self):
        self.assertEqual(
            sorted(m.id for m in get_checks(severity_min=Severity.HIGH)), ["IAM-1", "S3-1"]
        )

    def test_par_identifiants(self):
        self.assertEqual([m.id for m in get_checks(ids=["iam-1"])], ["IAM-1"])

    def test_combinaison(self):
        self.assertEqual([m.id for m in get_checks(service="s3", severity_min=Severity.HIGH)],
                         ["S3-1"])


class TestIsolationDesPannes(BaseRegistre):
    def test_exception_capturee(self):
        @check(id="BOOM", title="Explose", severity=Severity.HIGH, service="s3")
        def boom(inv):
            raise KeyError("Buckets")

        findings = run_checks(Inventory())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, Status.NOT_AVAILABLE)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertIn("Buckets", findings[0].details)

    def test_les_autres_continuent(self):
        @check(id="A", title="A", severity=Severity.LOW, service="s3")
        def a(inv):
            return [f("A")]

        @check(id="BOOM", title="B", severity=Severity.LOW, service="s3")
        def boom(inv):
            raise RuntimeError("panne")

        @check(id="C", title="C", severity=Severity.LOW, service="s3")
        def c(inv):
            return [f("C")]

        self.assertEqual([x.check_id for x in run_checks(Inventory())], ["A", "BOOM", "C"])

    def test_retour_none_tolere(self):
        @check(id="N", title="N", severity=Severity.LOW, service="s3")
        def n(inv):
            return None

        self.assertEqual(run_checks(Inventory()), [])

    def test_interruption_clavier_non_capturee(self):
        """Ctrl+C doit interrompre le scan, pas produire un finding."""

        @check(id="K", title="K", severity=Severity.LOW, service="s3")
        def k(inv):
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            run_checks(Inventory())


class TestMakeFinding(BaseRegistre):
    def test_herite_des_metadonnees(self):
        @check(
            id="M-1",
            title="Titre",
            severity=Severity.MEDIUM,
            service="s3",
            cis="1.2",
            remediation="corriger",
        )
        def m(inv):
            return []

        finding = make_finding("M-1", Resource(id="r"), ok=False, details="d")
        self.assertEqual(finding.title, "Titre")
        self.assertEqual(finding.severity, Severity.MEDIUM)
        self.assertEqual(finding.cis, "1.2")
        self.assertEqual(finding.remediation, "corriger")
        self.assertEqual(finding.status, Status.FAIL)


class TestChargementAutomatique(unittest.TestCase):
    def test_tous_les_checks_sont_charges(self):
        load_all_checks()
        services = {m.service for m in get_checks()}
        self.assertEqual(services, {"s3", "iam", "ec2", "cloudtrail"})
        self.assertGreaterEqual(len(get_checks()), 25)

    def test_identifiants_uniques_et_documentes(self):
        load_all_checks()
        metas = get_checks()
        self.assertEqual(len(metas), len({m.id for m in metas}))
        sans_remediation = [m.id for m in metas if not m.remediation.strip()]
        self.assertEqual(sans_remediation, [], "chaque check doit porter une remediation")


if __name__ == "__main__":
    unittest.main(verbosity=2)
