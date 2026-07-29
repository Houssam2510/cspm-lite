#!/usr/bin/env python3
"""Genere learning/cspm-lite-guide.pdf a partir des fichiers Markdown du dossier.

Aucune dependance externe : le PDF (A4, polices base-14, WinAnsi) est ecrit a la main.
Sous-ensemble Markdown supporte : titres # a ####, paragraphes, listes a puces et
numerotees, blocs de code ```, tableaux pipe, regles ---, et les styles inline
**gras**, *italique*, `code`, [texte](lien).

Usage : python3 learning/tools/build_pdf.py
"""

from __future__ import annotations

import re
import unicodedata
from datetime import date
from pathlib import Path

# --------------------------------------------------------------------------- #
# Metriques des polices base-14 (unites/1000)
# --------------------------------------------------------------------------- #

_HELV = (
    "278 278 355 556 556 889 667 191 333 333 389 584 278 333 278 278 "
    "556 556 556 556 556 556 556 556 556 556 278 278 584 584 584 556 "
    "1015 667 667 722 722 667 611 778 722 278 500 667 556 833 722 778 "
    "667 778 722 667 611 722 667 944 667 667 611 278 278 278 469 556 "
    "333 556 556 500 556 556 278 556 556 222 222 500 222 833 556 556 "
    "556 556 333 500 278 556 500 722 500 500 500 334 260 334 584"
)
_HELVB = (
    "278 333 474 556 556 889 722 238 333 333 389 584 278 333 278 278 "
    "556 556 556 556 556 556 556 556 556 556 333 333 584 584 584 611 "
    "975 722 722 722 722 667 611 778 722 278 556 722 611 833 722 778 "
    "667 778 722 667 611 722 667 944 667 667 611 333 278 333 584 556 "
    "333 556 611 556 611 556 333 611 611 278 278 556 278 889 611 611 "
    "611 611 389 556 333 611 556 778 556 556 500 389 280 389 584"
)


def _mk(spec: str) -> dict[str, int]:
    return {chr(32 + i): int(w) for i, w in enumerate(spec.split())}


WIDTHS = {"r": _mk(_HELV), "b": _mk(_HELVB), "i": _mk(_HELV)}
FONT_OF = {"r": "/F1", "b": "/F2", "c": "/F3", "i": "/F4"}


def char_width(ch: str, style: str) -> int:
    if style == "c":
        return 600
    table = WIDTHS[style]
    if ch in table:
        return table[ch]
    base = "".join(c for c in unicodedata.normalize("NFD", ch) if not unicodedata.combining(c))
    if base and base[0] in table:
        return table[base[0]]
    return 556


def text_width(s: str, style: str, size: float) -> float:
    return sum(char_width(c, style) for c in s) * size / 1000.0


# --------------------------------------------------------------------------- #
# Mise en page
# --------------------------------------------------------------------------- #

PAGE_W, PAGE_H = 595.28, 841.89
ML, MR, MT, MB = 56.0, 56.0, 64.0, 58.0
CONTENT_W = PAGE_W - ML - MR

BODY_SIZE, BODY_LEAD = 9.6, 13.4
CODE_SIZE, CODE_LEAD = 8.2, 11.0
TABLE_SIZE, TABLE_LEAD = 8.3, 11.2

INK = (0.11, 0.12, 0.14)
ACCENT = (0.09, 0.26, 0.48)
MUTED = (0.42, 0.45, 0.50)
RULE = (0.80, 0.82, 0.86)
CODE_BG = (0.955, 0.957, 0.965)
HEAD_BG = (0.92, 0.94, 0.97)

HEADINGS = {1: (18.5, 22.0, 6.0, ACCENT), 2: (13.5, 16.0, 5.0, ACCENT),
            3: (11.0, 11.0, 3.5, INK), 4: (9.8, 9.0, 3.0, INK)}


def esc(s: str) -> bytes:
    raw = s.encode("cp1252", "replace")
    return raw.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")


def rgb(c: tuple[float, float, float]) -> bytes:
    return f"{c[0]:.3f} {c[1]:.3f} {c[2]:.3f}".encode()


# --------------------------------------------------------------------------- #
# Parsing Markdown
# --------------------------------------------------------------------------- #

INLINE_RE = re.compile(r"(\*\*.+?\*\*|`[^`]+`|\*[^*\n]+?\*)")
LINK_RE = re.compile(r"\[([^\]]+)\]\([^)]*\)")


def to_chars(text: str) -> list[tuple[str, str]]:
    """Transforme du texte inline en liste de (caractere, style)."""
    text = LINK_RE.sub(r"\1", text)
    out: list[tuple[str, str]] = []
    for part in INLINE_RE.split(text):
        if not part:
            continue
        if part.startswith("**") and part.endswith("**") and len(part) > 4:
            body, style = part[2:-2], "b"
        elif part.startswith("`") and part.endswith("`") and len(part) > 2:
            body, style = part[1:-1], "c"
        elif part.startswith("*") and part.endswith("*") and len(part) > 2:
            body, style = part[1:-1], "i"
        else:
            body, style = part, "r"
        out.extend((c, style) for c in body)
    return out


Token = list[tuple[str, str]]


def tokenize(chars: list[tuple[str, str]]) -> list[Token]:
    tokens: list[Token] = []
    cur: Token = []
    for ch, st in chars:
        if ch == " ":
            if cur:
                tokens.append(cur)
                cur = []
        else:
            cur.append((ch, st))
    if cur:
        tokens.append(cur)
    return tokens


def tok_width(tok: Token, size: float) -> float:
    return sum(char_width(c, s) for c, s in tok) * size / 1000.0


def wrap(chars: list[tuple[str, str]], size: float, width: float) -> list[Token]:
    """Retourne des lignes ; chaque ligne est une suite de (char, style) avec espaces."""
    space = text_width(" ", "r", size)
    lines: list[Token] = []
    line: Token = []
    w = 0.0
    for tok in tokenize(chars):
        tw = tok_width(tok, size)
        add = tw if not line else tw + space
        if line and w + add > width:
            lines.append(line)
            line, w = list(tok), tw
        else:
            if line:
                line.append((" ", "r"))
            line.extend(tok)
            w += add
    if line:
        lines.append(line)
    return lines or [[]]


def parse(md: str) -> list[tuple]:
    """Retourne une liste de blocs ('h',n,txt) ('p',txt) ('ul',txt) ('ol',txt)
    ('code',lines) ('table',rows) ('hr',)."""
    blocks: list[tuple] = []
    lines = md.splitlines()
    i, n = 0, len(lines)
    para: list[str] = []

    def flush() -> None:
        if para:
            blocks.append(("p", " ".join(x.strip() for x in para)))
            para.clear()

    while i < n:
        ln = lines[i]
        s = ln.strip()
        if s.startswith("```"):
            flush()
            i += 1
            buf: list[str] = []
            while i < n and not lines[i].strip().startswith("```"):
                buf.append(lines[i])
                i += 1
            i += 1
            blocks.append(("code", buf))
            continue
        if not s:
            flush()
            i += 1
            continue
        m = re.match(r"^(#{1,4})\s+(.*)$", s)
        if m:
            flush()
            blocks.append(("h", len(m.group(1)), m.group(2).strip()))
            i += 1
            continue
        if re.fullmatch(r"-{3,}|\*{3,}|_{3,}", s):
            flush()
            blocks.append(("hr",))
            i += 1
            continue
        if s.startswith("|") and i + 1 < n and re.fullmatch(
            r"\|[\s:|-]+\|", lines[i + 1].strip()
        ):
            flush()
            rows = [[c.strip() for c in s.strip("|").split("|")]]
            i += 2
            while i < n and lines[i].strip().startswith("|"):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            blocks.append(("table", rows))
            continue
        m = re.match(r"^[-*]\s+(.*)$", s)
        if m:
            flush()
            item = m.group(1)
            i += 1
            while i < n and lines[i].startswith(("  ", "\t")) and lines[i].strip() \
                    and not re.match(r"^\s*[-*]\s", lines[i]):
                item += " " + lines[i].strip()
                i += 1
            blocks.append(("ul", item))
            continue
        m = re.match(r"^(\d+)\.\s+(.*)$", s)
        if m:
            flush()
            item = m.group(2)
            num = m.group(1)
            i += 1
            while i < n and lines[i].startswith(("  ", "\t")) and lines[i].strip() \
                    and not re.match(r"^\s*(\d+\.|[-*])\s", lines[i]):
                item += " " + lines[i].strip()
                i += 1
            blocks.append(("ol", f"{num}.", item))
            continue
        para.append(s)
        i += 1
    flush()
    return blocks


# --------------------------------------------------------------------------- #
# Rendu
# --------------------------------------------------------------------------- #


class Renderer:
    def __init__(self) -> None:
        self.pages: list[list[bytes]] = []
        self.ops: list[bytes] = []
        self.y = PAGE_H - MT
        self.toc: list[tuple[int, str, int]] = []

    # -- primitives ------------------------------------------------------- #
    def page_break(self) -> None:
        self.pages.append(self.ops)
        self.ops = []
        self.y = PAGE_H - MT

    def need(self, h: float) -> None:
        if self.y - h < MB:
            self.page_break()

    def rect(self, x: float, y: float, w: float, h: float,
             color: tuple[float, float, float]) -> None:
        self.ops.append(b"q " + rgb(color) + f" rg {x:.2f} {y:.2f} {w:.2f} {h:.2f} re f Q".encode())

    def line(self, x1: float, y1: float, x2: float, y2: float,
             color: tuple[float, float, float] = RULE, w: float = 0.6) -> None:
        self.ops.append(
            b"q " + rgb(color) + f" RG {w} w {x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S Q".encode()
        )

    def draw_line_tokens(self, x: float, y: float, toks: Token, size: float,
                         color: tuple[float, float, float], force: str | None = None) -> None:
        cx = x
        run_txt: list[str] = []
        run_style = ""
        for ch, st in toks:
            st = force or st
            if st != run_style and run_txt:
                cx = self._emit(cx, y, "".join(run_txt), run_style, size, color)
                run_txt = []
            run_style = st
            run_txt.append(ch)
        if run_txt:
            self._emit(cx, y, "".join(run_txt), run_style, size, color)

    def _emit(self, x: float, y: float, s: str, style: str, size: float,
              color: tuple[float, float, float]) -> float:
        if s:
            self.ops.append(
                b"BT " + rgb(color) + b" rg " + FONT_OF[style].encode()
                + f" {size} Tf {x:.2f} {y:.2f} Td (".encode() + esc(s) + b") Tj ET"
            )
        return x + text_width(s, "r" if style == "i" else style, size)

    def para(self, chars: list[tuple[str, str]], x: float, width: float,
             size: float = BODY_SIZE, lead: float = BODY_LEAD,
             color: tuple[float, float, float] = INK, force: str | None = None) -> None:
        for ln in wrap(chars, size, width):
            self.need(lead)
            self.y -= lead
            self.draw_line_tokens(x, self.y, ln, size, color, force)

    # -- blocs ------------------------------------------------------------ #
    def heading(self, level: int, text: str) -> None:
        size, before, after, color = HEADINGS[level]
        if level == 1 and self.ops:
            self.page_break()
        self.y -= before
        chars = to_chars(text)
        lines = wrap(chars, size, CONTENT_W)
        self.need(len(lines) * (size + 3) + after + 6)
        if level <= 2:
            self.toc.append((level, text, len(self.pages)))
        for ln in lines:
            self.y -= size + 3
            self.draw_line_tokens(ML, self.y, ln, size, color, force="b")
        if level == 1:
            self.y -= 6
            self.line(ML, self.y, PAGE_W - MR, self.y, ACCENT, 1.2)
        self.y -= after

    def bullet(self, marker: str, text: str, indent: float = 15.0) -> None:
        self.need(BODY_LEAD)
        lines = wrap(to_chars(text), BODY_SIZE, CONTENT_W - indent)
        for k, ln in enumerate(lines):
            self.need(BODY_LEAD)
            self.y -= BODY_LEAD
            if k == 0:
                self._emit(ML + 3, self.y, marker, "r", BODY_SIZE, ACCENT)
            self.draw_line_tokens(ML + indent, self.y, ln, BODY_SIZE, INK)

    def code(self, lines: list[str]) -> None:
        maxc = max(1, int((CONTENT_W - 16) / (600 * CODE_SIZE / 1000.0)))
        wrapped: list[str] = []
        for ln in lines:
            ln = ln.rstrip()
            if not ln:
                wrapped.append("")
            while ln:
                wrapped.append(ln[:maxc])
                ln = ln[maxc:]
        self.y -= 4
        i = 0
        while i < len(wrapped):
            avail = self.y - MB - 10
            fit = max(1, int(avail // CODE_LEAD))
            chunk = wrapped[i:i + fit]
            if not chunk or (avail < CODE_LEAD * 2 and i < len(wrapped)):
                self.page_break()
                continue
            h = len(chunk) * CODE_LEAD + 8
            self.rect(ML, self.y - h, CONTENT_W, h, CODE_BG)
            self.line(ML, self.y - h, ML, self.y, ACCENT, 1.6)
            self.y -= 4
            for ln in chunk:
                self.y -= CODE_LEAD
                self._emit(ML + 9, self.y, ln, "c", CODE_SIZE, (0.16, 0.18, 0.22))
            self.y -= 4
            i += len(chunk)
            if i < len(wrapped):
                self.page_break()
        self.y -= 5

    def table(self, rows: list[list[str]]) -> None:
        ncol = max(len(r) for r in rows)
        rows = [r + [""] * (ncol - len(r)) for r in rows]
        nat = [max(text_width(r[c], "r", TABLE_SIZE) + 12 for r in rows) for c in range(ncol)]
        total = sum(nat)
        widths = ([w * CONTENT_W / total for w in nat] if total > CONTENT_W
                  else [w + (CONTENT_W - total) / ncol for w in nat])
        self.y -= 4
        for ri, row in enumerate(rows):
            cells = [wrap(to_chars(row[c]), TABLE_SIZE, widths[c] - 10) for c in range(ncol)]
            h = max(len(c) for c in cells) * TABLE_LEAD + 6
            if self.y - h < MB:
                self.page_break()
            top = self.y
            if ri == 0:
                self.rect(ML, top - h, CONTENT_W, h, HEAD_BG)
            x = ML
            for c in range(ncol):
                yy = top - 4
                for ln in cells[c]:
                    yy -= TABLE_LEAD - 2
                    self.draw_line_tokens(x + 5, yy, ln, TABLE_SIZE, INK,
                                          force="b" if ri == 0 else None)
                    yy -= 2
                x += widths[c]
            self.line(ML, top - h, ML + CONTENT_W, top - h, RULE, 0.5)
            self.y = top - h
        self.y -= 8

    def hr(self) -> None:
        self.need(14)
        self.y -= 8
        self.line(ML, self.y, PAGE_W - MR, self.y, RULE, 0.7)
        self.y -= 6

    def render(self, blocks: list[tuple]) -> None:
        for b in blocks:
            kind = b[0]
            if kind == "h":
                self.heading(b[1], b[2])
            elif kind == "p":
                self.y -= 3
                self.para(to_chars(b[1]), ML, CONTENT_W)
                self.y -= 3
            elif kind == "ul":
                self.bullet("•", b[1])
            elif kind == "ol":
                self.bullet(b[1], b[2], indent=20.0)
            elif kind == "code":
                self.code(b[1])
            elif kind == "table":
                self.table(b[1])
            elif kind == "hr":
                self.hr()

    def finish(self) -> None:
        if self.ops:
            self.pages.append(self.ops)


# --------------------------------------------------------------------------- #
# Assemblage PDF
# --------------------------------------------------------------------------- #


def cover_ops(title: str, subtitle: str, meta: list[str]) -> list[bytes]:
    r = Renderer()
    r.rect(0, PAGE_H - 200, PAGE_W, 200, (0.09, 0.26, 0.48))
    y = PAGE_H - 105
    for ln in wrap(to_chars(title), 27, CONTENT_W):
        r.draw_line_tokens(ML, y, ln, 27, (1, 1, 1), force="b")
        y -= 32
    for ln in wrap(to_chars(subtitle), 12.5, CONTENT_W):
        r.draw_line_tokens(ML, y - 4, ln, 12.5, (0.85, 0.89, 0.95))
        y -= 16
    y = PAGE_H - 265
    for m in meta:
        for ln in wrap(to_chars(m), 10.5, CONTENT_W):
            r.draw_line_tokens(ML, y, ln, 10.5, INK)
            y -= 15
        y -= 4
    r.line(ML, 84, PAGE_W - MR, 84, RULE, 0.7)
    r.draw_line_tokens(ML, 68, to_chars("cspm-lite - guide d'apprentissage"), 9, MUTED)
    return r.ops


def toc_pages(entries: list[tuple[int, str, int]], offset_pages: int) -> list[list[bytes]]:
    r = Renderer()
    r.y = PAGE_H - MT
    r.y -= 22
    r.draw_line_tokens(ML, r.y, to_chars("Table des matieres"), 18.5, ACCENT, force="b")
    r.y -= 8
    r.line(ML, r.y, PAGE_W - MR, r.y, ACCENT, 1.2)
    r.y -= 14
    for level, text, body_idx in entries:
        size = 10.2 if level == 1 else 9.2
        indent = 0.0 if level == 1 else 16.0
        style = "b" if level == 1 else "r"
        color = INK if level == 1 else MUTED
        if r.y - 16 < MB:
            r.page_break()
        r.y -= 15 if level == 1 else 13
        num = str(offset_pages + body_idx + 1)
        numw = text_width(num, "r", size)
        avail = CONTENT_W - indent - numw - 12
        line = wrap(to_chars(text), size, avail)[0]
        r.draw_line_tokens(ML + indent, r.y, line, size, color, force=style)
        used = sum(char_width(c, style) for c, _ in line) * size / 1000.0
        dots_x = ML + indent + used + 4
        r.line(dots_x, r.y + 2.5, PAGE_W - MR - numw - 4, r.y + 2.5, (0.85, 0.86, 0.89), 0.5)
        r._emit(PAGE_W - MR - numw, r.y, num, style, size, color)
    r.finish()
    return r.pages


def footer(page_no: int, total: int, label: str) -> list[bytes]:
    r = Renderer()
    r.line(ML, MB - 16, PAGE_W - MR, MB - 16, RULE, 0.5)
    r.draw_line_tokens(ML, MB - 28, to_chars(label), 8, MUTED)
    txt = f"{page_no} / {total}"
    w = text_width(txt, "r", 8)
    r.draw_line_tokens(PAGE_W - MR - w, MB - 28, to_chars(txt), 8, MUTED)
    return r.ops


def build(pages: list[list[bytes]], out: Path, label: str) -> None:
    total = len(pages)
    objs: list[bytes] = []

    def add(data: bytes) -> int:
        objs.append(data)
        return len(objs)

    font_ids = {}
    for key, base in (("F1", "Helvetica"), ("F2", "Helvetica-Bold"),
                      ("F3", "Courier"), ("F4", "Helvetica-Oblique")):
        font_ids[key] = add(
            f"<< /Type /Font /Subtype /Type1 /BaseFont /{base} "
            f"/Encoding /WinAnsiEncoding >>".encode()
        )
    res = ("<< /Font << " + " ".join(f"/{k} {v} 0 R" for k, v in font_ids.items()) + " >> >>")

    pages_id = add(b"")  # reserve
    page_ids: list[int] = []
    for idx, ops in enumerate(pages, start=1):
        body = b"\n".join(ops + footer(idx, total, label)) + b"\n"
        cid = add(b"<< /Length " + str(len(body)).encode() + b" >>\nstream\n" + body + b"endstream")
        pid = add(
            f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {PAGE_W:.2f} {PAGE_H:.2f}] "
            f"/Resources {res} /Contents {cid} 0 R >>".encode()
        )
        page_ids.append(pid)
    objs[pages_id - 1] = (
        "<< /Type /Pages /Count " + str(total) + " /Kids ["
        + " ".join(f"{p} 0 R" for p in page_ids) + "] >>"
    ).encode()
    cat = add(f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode())

    buf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for i, data in enumerate(objs, start=1):
        offsets.append(len(buf))
        buf += f"{i} 0 obj\n".encode() + data + b"\nendobj\n"
    xref = len(buf)
    buf += f"xref\n0 {len(objs) + 1}\n".encode()
    buf += b"0000000000 65535 f \n"
    for off in offsets[1:]:
        buf += f"{off:010d} 00000 n \n".encode()
    buf += (f"trailer\n<< /Size {len(objs) + 1} /Root {cat} 0 R >>\n"
            f"startxref\n{xref}\n%%EOF\n").encode()
    out.write_bytes(bytes(buf))


DOCS = [
    "README.md",
    "01-le-projet.md",
    "02-roadmap.md",
    "03-issues.md",
    "04-concepts-cles.md",
    "05-competences-et-valorisation.md",
    "06-journal-de-bord.md",
    "07-maximiser-le-bagage.md",
    "exercices/README.md",
]


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    body = Renderer()
    for name in DOCS:
        path = root / name
        if not path.exists():
            continue
        body.render(parse(path.read_text(encoding="utf-8")))
    body.finish()

    cover = cover_ops(
        "cspm-lite",
        "Construire un scanner de posture de securite cloud AWS, et comprendre "
        "pourquoi chaque brique existe",
        [
            "Guide de projet complet : architecture, roadmap en 10 phases, backlog de "
            "30 issues, fiches de concepts, valorisation professionnelle.",
            "Public : etudiant en genie informatique oriente cybersecurite, cloud et data.",
            "Effort estime : 60 a 90 heures, soit 10 a 12 semaines a raison de 6 a 8 h "
            "par semaine.",
            f"Genere le {date.today().isoformat()}.",
        ],
    )

    n_toc = len(toc_pages(body.toc, 0))
    offset = 1 + n_toc
    pages = [cover] + toc_pages(body.toc, offset) + body.pages
    out = root / "cspm-lite-guide.pdf"
    build(pages, out, "cspm-lite - guide d'apprentissage")
    print(f"OK : {out}  ({len(pages)} pages, {out.stat().st_size // 1024} Ko)")


if __name__ == "__main__":
    main()
