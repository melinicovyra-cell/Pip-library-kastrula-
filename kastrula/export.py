"""
kastrula.export — экспорт результатов: JSON, HTML, текстовый отчёт.
"""

from __future__ import annotations

import json
import html
import time
from dataclasses import asdict, is_dataclass
from datetime import datetime
from typing import Any, Optional
from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_serializable(obj: Any) -> Any:
    """Convert dataclass/objects to JSON-serializable dict."""
    if is_dataclass(obj) and not isinstance(obj, type):
        return {k: _to_serializable(v) for k, v in asdict(obj).items()}
    elif isinstance(obj, list):
        return [_to_serializable(i) for i in obj]
    elif isinstance(obj, dict):
        return {k: _to_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, bytes):
        return obj.hex()
    elif isinstance(obj, (int, float, str, bool, type(None))):
        return obj
    else:
        return str(obj)


# ---------------------------------------------------------------------------
# Report builder
# ---------------------------------------------------------------------------

class Report:
    """
    Сборщик отчёта для экспорта.

    >>> report = Report("Scan Report: example.com")
    >>> report.add_section("TLS Analysis", tls_result)
    >>> report.add_section("Open Ports", scan_result)
    >>> report.save_json("report.json")
    >>> report.save_html("report.html")
    """

    def __init__(self, title: str = "Kastrula Report", target: str = ""):
        self.title = title
        self.target = target
        self.timestamp = datetime.now().isoformat()
        self.sections: list[dict] = []
        self._meta: dict = {
            "tool": "kastrula",
            "version": "0.2.0",
        }

    def add_section(self, name: str, data: Any, notes: str = "") -> 'Report':
        """Добавить секцию в отчёт."""
        self.sections.append({
            "name": name,
            "data": _to_serializable(data),
            "notes": notes,
        })
        return self

    def add_raw(self, name: str, text: str) -> 'Report':
        """Добавить текстовую секцию."""
        self.sections.append({
            "name": name,
            "data": text,
            "notes": "",
        })
        return self

    # ── JSON ───────────────────────────────────────────────────────────────

    def to_json(self, indent: int = 2) -> str:
        """Экспорт в JSON строку."""
        return json.dumps({
            "meta": self._meta,
            "title": self.title,
            "target": self.target,
            "timestamp": self.timestamp,
            "sections": self.sections,
        }, indent=indent, ensure_ascii=False, default=str)

    def save_json(self, path: str) -> str:
        """Сохранить JSON отчёт."""
        Path(path).write_text(self.to_json(), encoding="utf-8")
        return path

    # ── HTML ───────────────────────────────────────────────────────────────

    def to_html(self) -> str:
        """Экспорт в HTML страницу."""
        sections_html = ""

        for section in self.sections:
            name = html.escape(section["name"])
            data = section["data"]
            notes = html.escape(section.get("notes", ""))

            content = self._render_data_html(data)

            sections_html += f"""
            <div class="section">
                <h2>{name}</h2>
                {f'<p class="notes">{notes}</p>' if notes else ''}
                <div class="content">{content}</div>
            </div>
            """

        return f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{html.escape(self.title)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
            background: #0a0e17;
            color: #c9d1d9;
            padding: 20px;
            line-height: 1.6;
        }}
        .header {{
            background: linear-gradient(135deg, #161b22, #1c2333);
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 24px;
            text-align: center;
        }}
        .header h1 {{
            color: #58a6ff;
            font-size: 24px;
            margin-bottom: 8px;
        }}
        .header .meta {{
            color: #8b949e;
            font-size: 13px;
        }}
        .header .target {{
            color: #f0883e;
            font-size: 18px;
            margin-top: 8px;
        }}
        .section {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 10px;
            padding: 24px;
            margin-bottom: 16px;
        }}
        .section h2 {{
            color: #58a6ff;
            font-size: 16px;
            margin-bottom: 16px;
            padding-bottom: 8px;
            border-bottom: 1px solid #21262d;
        }}
        .notes {{
            color: #8b949e;
            font-size: 13px;
            margin-bottom: 12px;
            font-style: italic;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        th {{
            background: #21262d;
            color: #58a6ff;
            padding: 8px 12px;
            text-align: left;
            font-weight: 600;
        }}
        td {{
            padding: 6px 12px;
            border-bottom: 1px solid #21262d;
        }}
        tr:hover td {{
            background: #1c2333;
        }}
        .tag {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
        }}
        .tag-green {{ background: #1b4332; color: #3fb950; }}
        .tag-red {{ background: #4c1d1d; color: #f85149; }}
        .tag-yellow {{ background: #3d2e00; color: #d29922; }}
        .tag-blue {{ background: #0c2d6b; color: #58a6ff; }}
        pre {{
            background: #0d1117;
            border: 1px solid #21262d;
            border-radius: 6px;
            padding: 16px;
            overflow-x: auto;
            font-size: 12px;
            line-height: 1.5;
        }}
        .kv {{ display: flex; margin-bottom: 4px; }}
        .kv .key {{ color: #8b949e; min-width: 140px; }}
        .kv .val {{ color: #c9d1d9; }}
        .footer {{
            text-align: center;
            color: #484f58;
            font-size: 12px;
            margin-top: 24px;
            padding: 16px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🍲 {html.escape(self.title)}</h1>
        {f'<div class="target">{html.escape(self.target)}</div>' if self.target else ''}
        <div class="meta">Generated: {self.timestamp} | kastrula v0.2.0</div>
    </div>

    {sections_html}

    <div class="footer">
        Generated by kastrula — сетевая кастрюля 🍲
    </div>
</body>
</html>"""

    def save_html(self, path: str) -> str:
        """Сохранить HTML отчёт."""
        Path(path).write_text(self.to_html(), encoding="utf-8")
        return path

    # ── Text ───────────────────────────────────────────────────────────────

    def to_text(self) -> str:
        """Экспорт в текстовый формат."""
        lines = [
            f"{'=' * 60}",
            f"  🍲 {self.title}",
            f"  Target: {self.target}" if self.target else "",
            f"  Time: {self.timestamp}",
            f"{'=' * 60}",
            "",
        ]

        for section in self.sections:
            lines.append(f"── {section['name']} {'─' * (50 - len(section['name']))}")
            lines.append("")
            data = section["data"]

            if isinstance(data, str):
                lines.append(data)
            elif isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, (list, dict)):
                        lines.append(f"  {k}:")
                        lines.append(f"    {json.dumps(v, ensure_ascii=False, default=str)}")
                    else:
                        lines.append(f"  {k}: {v}")
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        parts = [f"{k}={v}" for k, v in item.items()]
                        lines.append(f"  {' | '.join(parts)}")
                    else:
                        lines.append(f"  {item}")
            else:
                lines.append(f"  {data}")

            lines.append("")

        lines.append(f"{'=' * 60}")
        lines.append("  Generated by kastrula 🍲")
        return "\n".join(lines)

    def save_text(self, path: str) -> str:
        """Сохранить текстовый отчёт."""
        Path(path).write_text(self.to_text(), encoding="utf-8")
        return path

    # ── Helpers ─────────────────────────────────────────────────────────────

    def _render_data_html(self, data: Any, depth: int = 0) -> str:
        """Render data as HTML."""
        if isinstance(data, str):
            return f"<pre>{html.escape(data)}</pre>"

        elif isinstance(data, dict):
            rows = ""
            for k, v in data.items():
                if isinstance(v, (dict, list)):
                    val_html = self._render_data_html(v, depth + 1)
                else:
                    val_html = html.escape(str(v))
                rows += f'<div class="kv"><span class="key">{html.escape(str(k))}</span><span class="val">{val_html}</span></div>'
            return rows

        elif isinstance(data, list):
            if not data:
                return "<em>empty</em>"

            # If list of dicts — render as table
            if isinstance(data[0], dict):
                keys = list(data[0].keys())
                header = "".join(f"<th>{html.escape(str(k))}</th>" for k in keys)
                rows = ""
                for item in data:
                    cells = "".join(
                        f"<td>{html.escape(str(item.get(k, '')))}</td>"
                        for k in keys
                    )
                    rows += f"<tr>{cells}</tr>"
                return f"<table><thead><tr>{header}</tr></thead><tbody>{rows}</tbody></table>"
            else:
                items = "".join(f"<div>• {html.escape(str(i))}</div>" for i in data)
                return items

        else:
            return html.escape(str(data))
