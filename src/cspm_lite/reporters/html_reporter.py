"""Sortie HTML : un rapport autonome, lisible par un humain.

Contraintes de conception, toutes volontaires :

- **un seul fichier**, CSS et JS en ligne, aucun CDN. Un rapport de securite ne doit
  pas emettre de requete vers un tiers quand on l'ouvre : le nom des ressources
  auditees fuiterait dans les logs de ce tiers ;
- **aucune dependance** de rendu (pas de Jinja) : moins de surface d'attaque ;
- **lisible en theme clair et sombre**, via `prefers-color-scheme` ;
- **triable et filtrable** cote client, parce qu'un rapport de 300 lignes non
  filtrable n'est pas lu.
"""

from __future__ import annotations

import html

from cspm_lite.engine.models import SCHEMA_VERSION, ScanResult, Severity, Status

_SEVERITY_ORDER = [s.name for s in sorted(Severity, key=lambda s: s.weight, reverse=True)]

_CSS = """
:root {
  --bg: #ffffff; --fg: #16181d; --muted: #626873; --card: #f6f7f9;
  --line: #e2e5ea; --accent: #17427a;
  --critical: #b3261e; --high: #c2410c; --medium: #a16207; --low: #2563a8;
  --informational: #626873; --pass: #15803d;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14161a; --fg: #e8eaee; --muted: #9aa1ad; --card: #1c1f25;
    --line: #2b2f37; --accent: #7aa7e0;
    --critical: #f0736a; --high: #f59e5b; --medium: #e0b64a; --low: #7ab0e8;
    --informational: #9aa1ad; --pass: #5cc98a;
  }
}
:root[data-theme="dark"] {
  --bg: #14161a; --fg: #e8eaee; --muted: #9aa1ad; --card: #1c1f25;
  --line: #2b2f37; --accent: #7aa7e0;
  --critical: #f0736a; --high: #f59e5b; --medium: #e0b64a; --low: #7ab0e8;
  --informational: #9aa1ad; --pass: #5cc98a;
}
:root[data-theme="light"] {
  --bg: #ffffff; --fg: #16181d; --muted: #626873; --card: #f6f7f9;
  --line: #e2e5ea; --accent: #17427a;
  --critical: #b3261e; --high: #c2410c; --medium: #a16207; --low: #2563a8;
  --informational: #626873; --pass: #15803d;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 2rem 1.25rem 4rem; background: var(--bg); color: var(--fg);
  font: 15px/1.55 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
.wrap { max-width: 1100px; margin: 0 auto; }
h1 { font-size: 1.6rem; margin: 0 0 .25rem; letter-spacing: -.01em; }
.sub { color: var(--muted); font-size: .9rem; margin-bottom: 1.75rem; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: .75rem; margin-bottom: 1.75rem; }
.tile { background: var(--card); border: 1px solid var(--line); border-radius: 10px;
  padding: .9rem 1rem; }
.tile .k { font-size: .72rem; text-transform: uppercase; letter-spacing: .06em;
  color: var(--muted); }
.tile .v { font-size: 1.75rem; font-weight: 650; font-variant-numeric: tabular-nums;
  margin-top: .15rem; }
.gauge { height: 8px; border-radius: 99px; background: var(--line); overflow: hidden;
  margin-top: .6rem; }
.gauge > i { display: block; height: 100%; background: var(--accent); }
.controls { display: flex; flex-wrap: wrap; gap: .5rem; margin-bottom: 1rem;
  align-items: center; }
input[type=search], select {
  background: var(--card); color: var(--fg); border: 1px solid var(--line);
  border-radius: 8px; padding: .45rem .7rem; font: inherit; font-size: .88rem;
}
input[type=search] { flex: 1 1 260px; }
.tablewrap { overflow-x: auto; border: 1px solid var(--line); border-radius: 10px; }
table { border-collapse: collapse; width: 100%; font-size: .88rem; }
th, td { text-align: left; padding: .6rem .75rem; border-bottom: 1px solid var(--line);
  vertical-align: top; }
th { background: var(--card); font-weight: 600; cursor: pointer; user-select: none;
  white-space: nowrap; position: sticky; top: 0; }
tbody tr:last-child td { border-bottom: 0; }
tbody tr.detail td { background: var(--card); color: var(--muted); font-size: .84rem; }
.badge { display: inline-block; padding: .1rem .5rem; border-radius: 99px;
  font-size: .72rem; font-weight: 650; letter-spacing: .03em; border: 1px solid; }
.CRITICAL { color: var(--critical); border-color: var(--critical); }
.HIGH { color: var(--high); border-color: var(--high); }
.MEDIUM { color: var(--medium); border-color: var(--medium); }
.LOW { color: var(--low); border-color: var(--low); }
.INFORMATIONAL { color: var(--informational); border-color: var(--informational); }
.st-PASS { color: var(--pass); font-weight: 600; }
.st-FAIL { color: var(--critical); font-weight: 600; }
.st-NOT_AVAILABLE, .st-WARNING { color: var(--muted); font-weight: 600; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: .85em; word-break: break-all; }
.row { cursor: pointer; }
footer { margin-top: 2rem; color: var(--muted); font-size: .8rem; }
.warn { background: var(--card); border: 1px solid var(--line); border-left: 3px solid var(--high);
  border-radius: 8px; padding: .75rem 1rem; margin-bottom: 1.5rem; font-size: .86rem; }
"""

_JS = """
const rows = Array.from(document.querySelectorAll('tr.row'));
const q = document.getElementById('q');
const sev = document.getElementById('sev');
const st = document.getElementById('st');
function apply() {
  const t = q.value.toLowerCase(), s = sev.value, u = st.value;
  rows.forEach(r => {
    const ok = (!t || r.dataset.search.includes(t))
      && (!s || r.dataset.severity === s)
      && (!u || r.dataset.status === u);
    r.hidden = !ok;
    const d = r.nextElementSibling;
    if (d && d.classList.contains('detail')) d.hidden = true;
  });
  document.getElementById('shown').textContent = rows.filter(r => !r.hidden).length;
}
[q, sev, st].forEach(el => el.addEventListener('input', apply));
rows.forEach(r => r.addEventListener('click', () => {
  const d = r.nextElementSibling;
  if (d && d.classList.contains('detail')) d.hidden = !d.hidden;
}));
document.querySelectorAll('th[data-sort]').forEach((th, i) => {
  let asc = true;
  th.addEventListener('click', () => {
    const tb = th.closest('table').tBodies[0];
    const pairs = rows.map(r => [r, r.nextElementSibling]);
    pairs.sort((a, b) => {
      const x = a[0].dataset[th.dataset.sort], y = b[0].dataset[th.dataset.sort];
      return (asc ? 1 : -1) * String(x).localeCompare(String(y), undefined, {numeric: true});
    });
    asc = !asc;
    pairs.forEach(([r, d]) => { tb.appendChild(r); if (d) tb.appendChild(d); });
  });
});
apply();
"""


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def render_html(result: ScanResult) -> str:
    counts = result.counts_by_severity
    tuiles = [
        ("Score de posture", f"{result.score}", True),
        ("Conformes", str(len(result.passed)), False),
        ("En echec", str(len(result.failed)), False),
        ("Ressources", str(len({f.resource.id for f in result.findings})), False),
    ]
    tuiles += [(nom.capitalize(), str(counts.get(nom, 0)), False) for nom in _SEVERITY_ORDER if counts.get(nom)]

    html_tuiles = []
    for cle, valeur, jauge in tuiles:
        barre = f'<div class="gauge"><i style="width:{result.score}%"></i></div>' if jauge else ""
        html_tuiles.append(
            f'<div class="tile"><div class="k">{_e(cle)}</div>'
            f'<div class="v">{_e(valeur)}</div>{barre}</div>'
        )

    lignes = []
    for f in result.findings:
        recherche = " ".join(
            [f.check_id, f.title, f.resource.id, f.resource.name, f.details, f.cis]
        ).lower()
        lignes.append(
            f'<tr class="row" data-severity="{_e(f.severity.name)}" '
            f'data-status="{_e(f.status.value)}" data-check="{_e(f.check_id)}" '
            f'data-resource="{_e(f.resource.id)}" data-weight="{f.severity.weight:03d}" '
            f'data-search="{_e(recherche)}">'
            f'<td><span class="badge {_e(f.severity.name)}">{_e(f.severity.name)}</span></td>'
            f'<td class="st-{_e(f.status.value)}">{_e(f.status.value)}</td>'
            f"<td><code>{_e(f.check_id)}</code></td>"
            f"<td>{_e(f.title)}</td>"
            f'<td class="mono">{_e(f.resource.id)}</td>'
            f"<td>{_e(f.resource.region)}</td>"
            f"</tr>"
        )
        detail = []
        if f.details:
            detail.append(f"<b>Constat</b> : {_e(f.details)}")
        if f.remediation:
            detail.append(f"<b>Remediation</b> : {_e(f.remediation)}")
        if f.cis:
            detail.append(f"<b>CIS</b> : {_e(f.cis)}")
        for url in f.references:
            detail.append(f'<a href="{_e(url)}" rel="noreferrer noopener">{_e(url)}</a>')
        lignes.append(
            f'<tr class="detail" hidden><td colspan="6">{"<br>".join(detail) or "—"}</td></tr>'
        )

    avertissements = ""
    if result.errors:
        items = "".join(f"<li>{_e(e)}</li>" for e in result.errors)
        avertissements = (
            f'<div class="warn"><b>Collecte partielle</b> — certains appels ont echoue, '
            f"les controles concernes peuvent etre incomplets :<ul>{items}</ul></div>"
        )

    options_sev = "".join(f'<option value="{s}">{s}</option>' for s in _SEVERITY_ORDER)
    options_st = "".join(f'<option value="{s.value}">{s.value}</option>' for s in Status)

    return f"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>cspm-lite — rapport de posture</title>
<style>{_CSS}</style>
</head>
<body>
<div class="wrap">
  <h1>Rapport de posture AWS</h1>
  <div class="sub">
    Compte <code>{_e(result.account_id or "inconnu")}</code> ·
    {len(result.regions)} region(s) ·
    {_e(result.started_at.strftime("%Y-%m-%d %H:%M UTC"))} ·
    {result.duration_seconds}s
  </div>
  {avertissements}
  <div class="tiles">{"".join(html_tuiles)}</div>
  <div class="controls">
    <input type="search" id="q" placeholder="Filtrer : check, ressource, constat…">
    <select id="sev"><option value="">Toutes severites</option>{options_sev}</select>
    <select id="st"><option value="">Tous statuts</option>{options_st}</select>
    <span class="sub" style="margin:0"><b id="shown">0</b> / {len(result.findings)} findings</span>
  </div>
  <div class="tablewrap">
    <table>
      <thead><tr>
        <th data-sort="weight">Severite</th>
        <th data-sort="status">Statut</th>
        <th data-sort="check">Check</th>
        <th data-sort="check">Titre</th>
        <th data-sort="resource">Ressource</th>
        <th data-sort="resource">Region</th>
      </tr></thead>
      <tbody>{"".join(lignes)}</tbody>
    </table>
  </div>
  <footer>
    Genere par cspm-lite · schema {_e(SCHEMA_VERSION)} ·
    cliquer une ligne pour afficher la remediation, cliquer un en-tete pour trier.
  </footer>
</div>
<script>{_JS}</script>
</body>
</html>
"""
