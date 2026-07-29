"""Tests de l'exercice 2. Ne modifie pas ce fichier."""

import unittest

from commun import Finding, Resource, Severity, Status
from exercice import check, clear_registry, get_checks, run_checks


def f(check_id, status=Status.PASS, sev=Severity.LOW):
    return Finding(
        check_id=check_id, title="t", severity=sev, status=status, resource=Resource(id="r")
    )


class Base(unittest.TestCase):
    def setUp(self):
        clear_registry()

    tearDown = setUp


class TestEnregistrement(Base):
    def test_enregistre(self):
        @check(id="S3-001", title="PAB", severity=Severity.HIGH, service="s3")
        def c(inv):
            return [f("S3-001")]

        metas = get_checks()
        self.assertEqual(len(metas), 1)
        m = metas[0]
        self.assertEqual(m.id, "S3-001")
        self.assertEqual(m.title, "PAB")
        self.assertEqual(m.severity, Severity.HIGH)
        self.assertEqual(m.service, "s3")

    def test_fonction_renvoyee_intacte(self):
        @check(id="A", title="t", severity=Severity.LOW, service="s3")
        def c(inv):
            return [f("A")]

        self.assertTrue(callable(c))
        self.assertEqual(len(c({})), 1, "le decorateur doit renvoyer la fonction utilisable")

    def test_id_duplique(self):
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


class TestFiltres(Base):
    def setUp(self):
        clear_registry()
        specs = [
            ("S3-001", "s3", Severity.HIGH),
            ("S3-002", "S3", Severity.LOW),
            ("IAM-001", "iam", Severity.CRITICAL),
            ("NET-001", "ec2", Severity.MEDIUM),
        ]
        for cid, svc, sev in specs:

            @check(id=cid, title=cid, severity=sev, service=svc)
            def c(inv):
                return []

    def test_sans_filtre(self):
        self.assertEqual(len(get_checks()), 4)

    def test_par_service(self):
        ids = [m.id for m in get_checks(service="iam")]
        self.assertEqual(ids, ["IAM-001"])

    def test_service_insensible_casse(self):
        ids = sorted(m.id for m in get_checks(service="S3"))
        self.assertEqual(ids, ["S3-001", "S3-002"], "le filtre service doit ignorer la casse")

    def test_severite_min(self):
        ids = sorted(m.id for m in get_checks(severity_min=Severity.HIGH))
        self.assertEqual(ids, ["IAM-001", "S3-001"], "severity_min est inclusif (>=)")

    def test_filtres_combines(self):
        ids = [m.id for m in get_checks(service="s3", severity_min=Severity.HIGH)]
        self.assertEqual(ids, ["S3-001"])


class TestExecution(Base):
    def test_concatenation(self):
        @check(id="A", title="A", severity=Severity.LOW, service="s3")
        def a(inv):
            return [f("A"), f("A")]

        @check(id="B", title="B", severity=Severity.LOW, service="s3")
        def b(inv):
            return [f("B")]

        res = run_checks({})
        self.assertEqual([x.check_id for x in res], ["A", "A", "B"])

    def test_inventaire_transmis(self):
        vu = {}

        @check(id="A", title="A", severity=Severity.LOW, service="s3")
        def a(inv):
            vu.update(inv)
            return []

        run_checks({"buckets": [1, 2]})
        self.assertEqual(vu, {"buckets": [1, 2]}, "l'inventaire doit etre passe au check")

    def test_liste_explicite(self):
        @check(id="A", title="A", severity=Severity.LOW, service="s3")
        def a(inv):
            return [f("A")]

        @check(id="B", title="B", severity=Severity.LOW, service="iam")
        def b(inv):
            return [f("B")]

        res = run_checks({}, checks=get_checks(service="iam"))
        self.assertEqual([x.check_id for x in res], ["B"])


class TestIsolationDesPannes(Base):
    def test_exception_ne_propage_pas(self):
        @check(id="BOOM", title="Explose", severity=Severity.HIGH, service="s3")
        def boom(inv):
            raise KeyError("Buckets")

        res = run_checks({})  # ne doit pas lever
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].status, Status.NOT_AVAILABLE)
        self.assertEqual(res[0].check_id, "BOOM")
        self.assertEqual(res[0].title, "Explose")
        self.assertEqual(res[0].severity, Severity.HIGH)
        self.assertEqual(res[0].resource.id, "-")
        self.assertIn("Buckets", res[0].details, "details doit contenir le message d'erreur")

    def test_les_autres_checks_continuent(self):
        @check(id="A", title="A", severity=Severity.LOW, service="s3")
        def a(inv):
            return [f("A")]

        @check(id="BOOM", title="B", severity=Severity.HIGH, service="s3")
        def boom(inv):
            raise RuntimeError("panne")

        @check(id="C", title="C", severity=Severity.LOW, service="s3")
        def c(inv):
            return [f("C")]

        res = run_checks({})
        self.assertEqual([x.check_id for x in res], ["A", "BOOM", "C"])
        self.assertEqual(res[1].status, Status.NOT_AVAILABLE)
        self.assertEqual(res[2].status, Status.PASS)

    def test_un_seul_finding_par_panne(self):
        @check(id="BOOM", title="B", severity=Severity.LOW, service="s3")
        def boom(inv):
            raise ValueError("x")

        self.assertEqual(len(run_checks({})), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
