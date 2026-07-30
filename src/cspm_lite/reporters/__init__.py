"""Reporters : rendu d'un ScanResult dans differents formats."""

from cspm_lite.reporters.asff_reporter import render_asff
from cspm_lite.reporters.html_reporter import render_html
from cspm_lite.reporters.json_reporter import render_json
from cspm_lite.reporters.markdown_reporter import render_markdown

RENDERERS = {
    "json": render_json,
    "markdown": render_markdown,
    "html": render_html,
    "asff": render_asff,
}

__all__ = ["RENDERERS", "render_asff", "render_html", "render_json", "render_markdown"]
