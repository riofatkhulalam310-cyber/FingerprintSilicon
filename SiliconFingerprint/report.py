from __future__ import annotations

import html
import json

from .models import AnalysisResult


def render_json(result: AnalysisResult) -> str:
    return json.dumps(result.as_dict(), ensure_ascii=False, indent=2)


def render_markdown(result: AnalysisResult) -> str:
    lines = [
        "# SiliconFingerprint Report",
        "",
        f"**File:** `{result.file_name}`",
        f"**SHA256:** `{result.sha256}`",
        f"**MIME:** `{result.mime_guess}`",
        f"**Kesimpulan:** {result.summary}",
        f"**Keyakinan:** {result.confidence}",
        "",
        "## Temuan",
        "",
    ]
    for finding in result.findings:
        lines.extend(
            [
                f"- **{finding.title}**",
                f"  - Kategori: `{finding.category}`",
                f"  - Keyakinan: `{finding.confidence}`",
                f"  - Detail: {finding.detail}",
            ]
        )
    lines.extend(["", "## Batasan", ""])
    lines.extend([f"- {item}" for item in result.limitations])
    return "\n".join(lines) + "\n"


def render_html(result: AnalysisResult) -> str:
    finding_items = "\n".join(
        "<li>"
        f"<strong>{html.escape(finding.title)}</strong>"
        f"<div>Kategori: <code>{html.escape(finding.category)}</code></div>"
        f"<div>Keyakinan: <code>{html.escape(finding.confidence)}</code></div>"
        f"<p>{html.escape(finding.detail)}</p>"
        "</li>"
        for finding in result.findings
    )
    limitation_items = "\n".join(f"<li>{html.escape(item)}</li>" for item in result.limitations)
    return f"""<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SiliconFingerprint Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; line-height: 1.55; color: #1f2937; }}
    main {{ max-width: 920px; margin: 0 auto; }}
    code {{ background: #f3f4f6; padding: 2px 5px; border-radius: 4px; }}
    .summary {{ border-left: 4px solid #2563eb; padding: 12px 16px; background: #eff6ff; }}
    li {{ margin-bottom: 14px; }}
  </style>
</head>
<body>
<main>
  <h1>SiliconFingerprint Report</h1>
  <section class="summary">
    <p><strong>File:</strong> <code>{html.escape(result.file_name)}</code></p>
    <p><strong>SHA256:</strong> <code>{html.escape(result.sha256)}</code></p>
    <p><strong>MIME:</strong> {html.escape(result.mime_guess)}</p>
    <p><strong>Kesimpulan:</strong> {html.escape(result.summary)}</p>
    <p><strong>Keyakinan:</strong> {html.escape(result.confidence)}</p>
  </section>
  <h2>Temuan</h2>
  <ul>{finding_items}</ul>
  <h2>Batasan</h2>
  <ul>{limitation_items}</ul>
</main>
</body>
</html>
"""
