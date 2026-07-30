"""Rendu de l'historique : tendance du score, diff et metriques.

Regles de visualisation appliquees ici, dans l'ordre ou elles doivent l'etre :

1. **La forme d'abord.** Le score dans le temps est une evolution -> courbe. Les
   deltas (nouveaux / resolus) sont des grandeurs uniques -> des tuiles chiffrees,
   pas des graphiques. Tout n'a pas besoin d'etre un graphique.
2. **Une seule serie**, donc pas de legende : le titre nomme la serie, et le
   dernier point porte une etiquette directe.
3. **Un seul axe.** Jamais de second axe y : le score et le nombre de findings
   sont deux mesures d'echelles differentes, elles ne partagent pas un cadre.
4. **Domaine complet.** L'axe va de 0 a 100 parce qu'un score a un domaine naturel ;
   le tronquer exagererait visuellement les variations.
5. **Couleurs par role**, definies en variables CSS et declinees pour le theme
   sombre (pas un simple inversement). Le vert et le rouge des deltas sont des
   couleurs de statut, toujours accompagnees d'un glyphe : jamais la couleur seule.
6. **Une vue tableau** accompagne la courbe, pour l'accessibilite et la lecture
   exacte des valeurs.
"""

from __future__ import annotations

import html
from typing import Any

from cspm_lite.history import Diff, Metrics, ScanRow

# Largeur/hauteur du cadre de dessin, en unites SVG.
W, H = 760, 260
PAD_G, PAD_D, PAD_H, PAD_B = 46, 24, 24, 40

_CSS = """
.viz {
  color-scheme: light;
  --surface: #fcfcfb; --ink: #0b0b0b; --ink-2: #52514e; --muted: #898781;
  --grid: #e1e0d9; --axis: #c3c2b7; --series-1: #2a78d6;
  --good: #006300; --bad: #d03b3b; --ring: rgba(11,11,11,.10);
}
@media (prefers-color-scheme: dark) {
  :root:where(:not([data-theme="light"])) .viz {
    color-scheme: dark;
    --surface: #1a1a19; --ink: #ffffff; --ink-2: #c3c2b7; --muted: #898781;
    --grid: #2c2c2a; --axis: #383835; --series-1: #3987e5;
    --good: #0ca30c; --bad: #d03b3b; --ring: rgba(255,255,255,.10);
  }
}
:root[data-theme="dark"] .viz {
  color-scheme: dark;
  --surface: #1a1a19; --ink: #ffffff; --ink-2: #c3c2b7; --muted: #898781;
  --grid: #2c2c2a; --axis: #383835; --series-1: #3987e5;
  --good: #0ca30c; --bad: #d03b3b; --ring: rgba(255,255,255,.10);
}
* { box-sizing: border-box; }
body { margin: 0; padding: 2rem 1.25rem 4rem; background: var(--surface); color: var(--ink);
  font: 15px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
.wrap { max-width: 900px; margin: 0 auto; }
h1 { font-size: 1.5rem; margin: 0 0 .2rem; letter-spacing: -.01em; }
h2 { font-size: 1rem; margin: 2rem 0 .75rem; font-weight: 600; }
.sub { color: var(--ink-2); font-size: .88rem; margin-bottom: 1.5rem; }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: .75rem; }
.tile { border: 1px solid var(--ring); border-radius: 10px; padding: .85rem 1rem; }
.tile .k { font-size: .72rem; text-transform: uppercase; letter-spacing: .06em;
  color: var(--muted); }
.tile .v { font-size: 2rem; font-weight: 650; margin-top: .1rem;
  font-variant-numeric: tabular-nums; }
.tile .d { font-size: .8rem; font-weight: 600;
  font-variant-numeric: tabular-nums; }
.up { color: var(--good); } .down { color: var(--bad); } .flat { color: var(--muted); }
figure { margin: 0; }
figcaption { color: var(--ink-2); font-size: .82rem; margin-top: .5rem; }
svg { width: 100%; height: auto; display: block; overflow: visible; }
.gl { stroke: var(--grid); stroke-width: 1; }
.ax { stroke: var(--axis); stroke-width: 1; }
.tick { fill: var(--muted); font-size: 11px; font-variant-numeric: tabular-nums; }
.line { fill: none; stroke: var(--series-1); stroke-width: 2;
  stroke-linejoin: round; stroke-linecap: round; }
.dot { fill: var(--series-1); stroke: var(--surface); stroke-width: 2; }
.lbl { fill: var(--ink); font-size: 12px; font-weight: 650; font-variant-numeric: tabular-nums; }
.crosshair { stroke: var(--axis); stroke-width: 1; stroke-dasharray: 3 3; opacity: 0; }
.hit { fill: transparent; cursor: crosshair; }
.tip { position: fixed; pointer-events: none; opacity: 0; transition: opacity .1s;
  background: var(--surface); color: var(--ink); border: 1px solid var(--ring);
  border-radius: 8px; padding: .45rem .6rem; font-size: .8rem; white-space: nowrap;
  box-shadow: 0 4px 14px rgba(0,0,0,.14); font-variant-numeric: tabular-nums; }
table { border-collapse: collapse; width: 100%; font-size: .86rem; margin-top: .5rem; }
th, td { text-align: left; padding: .45rem .6rem; border-bottom: 1px solid var(--ring); }
th { color: var(--ink-2); font-weight: 600; }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85em;
  word-break: break-all; }
.empty { color: var(--muted); font-size: .88rem; }
details { margin-top: .75rem; }
summary { cursor: pointer; color: var(--ink-2); font-size: .85rem; }
"""

_JS = """
const svg = document.getElementById('chart');
if (svg) {
  const tip = document.getElementById('tip');
  const cross = document.getElementById('cross');
  const focus = document.getElementById('focus');
  const pts = JSON.parse(svg.dataset.points);
  svg.querySelectorAll('.hit').forEach(r => {
    const i = Number(r.dataset.i);
    const show = e => {
      const p = pts[i];
      cross.setAttribute('x1', p.x); cross.setAttribute('x2', p.x);
      cross.style.opacity = 1;
      focus.setAttribute('cx', p.x); focus.setAttribute('cy', p.y);
      focus.style.opacity = 1;
      tip.textContent = `${p.date} — score ${p.score} · ${p.fail} echec(s)`;
      tip.style.opacity = 1;
      tip.style.left = Math.min(e.clientX + 14, innerWidth - tip.offsetWidth - 8) + 'px';
      tip.style.top = (e.clientY - 34) + 'px';
    };
    r.addEventListener('mousemove', show);
    r.addEventListener('mouseenter', show);
    r.addEventListener('mouseleave', () => {
      tip.style.opacity = 0; cross.style.opacity = 0; focus.style.opacity = 0;
    });
  });
}
"""


def _e(v: object) -> str:
    return html.escape(str(v), quote=True)


def _sparkline(scores: list[float]) -> str:
    """Courbe miniature en caracteres, pour la sortie terminal."""
    if not scores:
        return ""
    blocs = "▁▂▃▄▅▆▇█"
    return "".join(blocs[min(7, int(s / 100 * 7.999))] for s in scores)


def _delta(scans: list[ScanRow]) -> tuple[str, str, str]:
    """(glyphe, texte, classe) de l'evolution du score entre les deux derniers scans."""
    if len(scans) < 2:
        return "", "premier scan", "flat"
    ecart = round(scans[-1].score - scans[-2].score, 1)
    if ecart > 0:
        return "▲", f"+{ecart} depuis le scan precedent", "up"
    if ecart < 0:
        return "▼", f"{ecart} depuis le scan precedent", "down"
    return "=", "stable depuis le scan precedent", "flat"


Point = dict[str, float | int | str]


def _chart(scans: list[ScanRow]) -> tuple[str, str]:
    """Renvoie (svg, json des points) pour la courbe du score."""
    if len(scans) < 2:
        return "", "[]"
    largeur = W - PAD_G - PAD_D
    hauteur = H - PAD_H - PAD_B
    n = len(scans)

    def x(i: int) -> float:
        return PAD_G + (largeur * i / (n - 1))

    def y(score: float) -> float:
        return PAD_H + hauteur * (1 - score / 100)

    points: list[Point] = [
        {
            "x": round(x(i), 1),
            "y": round(y(s.score), 1),
            "score": s.score,
            "fail": s.fail_count,
            "date": s.started_at.strftime("%Y-%m-%d %H:%M"),
        }
        for i, s in enumerate(scans)
    ]

    elements: list[str] = []
    for valeur in (0, 25, 50, 75, 100):
        yy = y(valeur)
        elements.append(
            f'<line class="gl" x1="{PAD_G}" y1="{yy:.1f}" x2="{W - PAD_D}" y2="{yy:.1f}"/>'
        )
        elements.append(
            f'<text class="tick" x="{PAD_G - 8}" y="{yy + 4:.1f}" text-anchor="end">{valeur}</text>'
        )
    elements.append(
        f'<line class="ax" x1="{PAD_G}" y1="{H - PAD_B}" x2="{W - PAD_D}" y2="{H - PAD_B}"/>'
    )

    chemin = " ".join(("M" if i == 0 else "L") + f"{p['x']} {p['y']}" for i, p in enumerate(points))
    elements.append(f'<path class="line" d="{chemin}"/>')

    # Marqueurs : 8 px de diametre, cercles cercles d'un anneau de 2 px de la
    # couleur de fond pour rester lisibles quand la courbe se replie sur elle-meme.
    for p in points:
        elements.append(f'<circle class="dot" cx="{p["x"]}" cy="{p["y"]}" r="4"/>')

    # Etiquettes d'axe : premiere et derniere date seulement, pour ne pas encombrer.
    for i in (0, n - 1):
        ancre = "start" if i == 0 else "end"
        elements.append(
            f'<text class="tick" x="{x(i):.1f}" y="{H - PAD_B + 18}" text-anchor="{ancre}">'
            f"{_e(scans[i].started_at.strftime('%d/%m'))}</text>"
        )

    # Etiquette directe sur le dernier point : une seule serie, donc pas de legende.
    dernier = points[-1]
    dx, dy = float(dernier["x"]), float(dernier["y"])
    elements.append(
        f'<text class="lbl" x="{dx - 10:.1f}" y="{dy - 12:.1f}" '
        f'text-anchor="end">{scans[-1].score}</text>'
    )

    elements.append(
        f'<line id="cross" class="crosshair" x1="0" y1="{PAD_H}" x2="0" y2="{H - PAD_B}"/>'
    )
    elements.append('<circle id="focus" class="dot" r="6" style="opacity:0" cx="-99" cy="-99"/>')

    # Zones de survol larges : la cible doit etre plus grande que le marqueur.
    pas = largeur / (n - 1)
    for i, p in enumerate(points):
        gauche = max(PAD_G, float(p["x"]) - pas / 2)
        elements.append(
            f'<rect class="hit" data-i="{i}" x="{gauche:.1f}" y="{PAD_H}" '
            f'width="{pas:.1f}" height="{hauteur}"/>'
        )

    import json

    svg = (
        f'<svg id="chart" viewBox="0 0 {W} {H}" role="img" '
        f'aria-label="Evolution du score de posture" '
        f"data-points='{json.dumps(points)}'>" + "".join(elements) + "</svg>"
    )
    return svg, json.dumps(points)


def render_history_markdown(scans: list[ScanRow], diff: Diff, metrics: Metrics) -> str:
    lignes = ["# Historique de posture", ""]
    if not scans:
        vide = "Aucun scan enregistre. Lancez `cspm-lite scan --save-to <db>`."
        return "\n".join([*lignes, vide])

    glyphe, texte, _ = _delta(scans)
    lignes.append(
        f"**Score actuel : {scans[-1].score} / 100** {glyphe} {texte} "
        f"— {len(scans)} scan(s) enregistre(s)"
    )
    lignes.append("")
    lignes.append(f"Tendance : `{_sparkline([s.score for s in scans])}`")
    lignes += [
        "",
        "| Scan | Date | Score | Conformes | Echecs |",
        "| --- | --- | --- | --- | --- |",
    ]
    for s in scans[-12:]:
        lignes.append(
            f"| #{s.id} | {s.started_at:%Y-%m-%d %H:%M} | {s.score} | "
            f"{s.pass_count} | {s.fail_count} |"
        )

    lignes += ["", "## Evolution depuis le scan precedent", ""]
    if diff.vide:
        lignes.append("Aucun changement.")
    else:
        lignes.append(
            f"{len(diff.nouveaux)} nouveau(x), {len(diff.resolus)} resolu(s), "
            f"{len(diff.persistants)} persistant(s)."
        )
        for titre, items in (("Nouveaux", diff.nouveaux), ("Resolus", diff.resolus)):
            if not items:
                continue
            lignes += ["", f"### {titre}", ""]
            for f in items:
                lignes.append(f"- **{f['check_id']}** ({f['severity']}) — `{f['resource_id']}`")

    lignes += ["", "## Metriques de pilotage", ""]
    lignes.append(f"- Delai moyen de correction : **{metrics.mttr_global} jour(s)**")
    for sev, valeur in metrics.mttr_par_severite.items():
        lignes.append(f"  - {sev} : {valeur} jour(s)")
    lignes.append(f"- Findings corriges : {metrics.corriges} · encore ouverts : {metrics.ouverts}")
    lignes.append(f"- Taux de recidive : {metrics.taux_de_recidive} %")
    if metrics.plus_anciens:
        lignes += ["", "Findings ouverts depuis le plus longtemps :", ""]
        for check, ressource, age in metrics.plus_anciens:
            lignes.append(f"- {check} — `{ressource}` — {age} jour(s)")
    return "\n".join(lignes) + "\n"


def _tuile(cle: str, valeur: str, delta: str = "", classe: str = "") -> str:
    bas = f'<div class="d {classe}">{_e(delta)}</div>' if delta else ""
    return (
        f'<div class="tile"><div class="k">{_e(cle)}</div>'
        f'<div class="v">{_e(valeur)}</div>{bas}</div>'
    )


def render_history_html(scans: list[ScanRow], diff: Diff, metrics: Metrics) -> str:
    if not scans:
        corps = '<p class="empty">Aucun scan enregistre.</p>'
        return _page(corps)

    glyphe, texte, classe = _delta(scans)
    svg, _ = _chart(scans)

    tuiles = "".join(
        [
            _tuile("Score actuel", str(scans[-1].score), f"{glyphe} {texte}", classe),
            _tuile("Echecs actifs", str(scans[-1].fail_count)),
            _tuile("Nouveaux", str(len(diff.nouveaux))),
            _tuile("Resolus", str(len(diff.resolus))),
            _tuile("Delai moyen de correction", f"{metrics.mttr_global} j"),
            _tuile("Taux de recidive", f"{metrics.taux_de_recidive} %"),
        ]
    )

    if svg:
        figure = (
            "<h2>Evolution du score de posture</h2>"
            f"<figure>{svg}"
            "<figcaption>Score pondere par severite, de 0 a 100. "
            "Survolez la courbe pour le detail d'un scan.</figcaption></figure>"
        )
    else:
        figure = '<p class="empty">Au moins deux scans sont necessaires pour tracer une courbe.</p>'

    table = "".join(
        f"<tr><td>#{s.id}</td><td>{_e(f'{s.started_at:%Y-%m-%d %H:%M}')}</td>"
        f'<td class="num">{s.score}</td><td class="num">{s.pass_count}</td>'
        f'<td class="num">{s.fail_count}</td></tr>'
        for s in reversed(scans)
    )
    vue_tableau = (
        "<details><summary>Vue tableau (valeurs exactes)</summary>"
        "<table><thead><tr><th>Scan</th><th>Date</th><th>Score</th>"
        "<th>Conformes</th><th>Echecs</th></tr></thead>"
        f"<tbody>{table}</tbody></table></details>"
    )

    def liste(titre: str, items: list[dict[str, Any]]) -> str:
        if not items:
            return ""
        lignes = "".join(
            f"<tr><td><code>{_e(f['check_id'])}</code></td><td>{_e(f['severity'])}</td>"
            f"<td><code>{_e(f['resource_id'])}</code></td></tr>"
            for f in items
        )
        return (
            f"<h2>{_e(titre)}</h2><table><thead><tr><th>Check</th><th>Severite</th>"
            f"<th>Ressource</th></tr></thead><tbody>{lignes}</tbody></table>"
        )

    mttr = "".join(
        f"<tr><td>{_e(sev)}</td><td class='num'>{valeur}</td></tr>"
        for sev, valeur in metrics.mttr_par_severite.items()
    )
    bloc_mttr = (
        "<h2>Delai de correction par severite</h2>"
        "<table><thead><tr><th>Severite</th><th>Jours</th></tr></thead>"
        f"<tbody>{mttr}</tbody></table>"
        if mttr
        else ""
    )

    corps = (
        f"<h1>Historique de posture</h1>"
        f'<div class="sub">Compte <code>{_e(scans[-1].account_id)}</code> · '
        f"{len(scans)} scan(s) · dernier le "
        f"{_e(f'{scans[-1].started_at:%Y-%m-%d %H:%M}')}</div>"
        f'<div class="tiles">{tuiles}</div>'
        f"{figure}{vue_tableau}"
        f"{liste('Nouveaux findings', diff.nouveaux)}"
        f"{liste('Findings resolus', diff.resolus)}"
        f"{bloc_mttr}"
    )
    return _page(corps)


def _page(corps: str) -> str:
    return f"""<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>cspm-lite — historique de posture</title>
<style>{_CSS}</style>
</head>
<body class="viz">
<div class="wrap">{corps}</div>
<div id="tip" class="tip"></div>
<script>{_JS}</script>
</body>
</html>
"""
