"""Report generator for ITShield (Phase 10).

Produces standalone HTML / JSON / text reports from a scan job's
results. The HTML report is self-contained (inline CSS, no external
dependencies) so it can be opened in any browser or attached to email.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from itshield.logging.logger import get_logger
from itshield.storage.database import Database

logger = get_logger(__name__)


class ReportFormat(str, Enum):
    HTML = "html"
    JSON = "json"
    TEXT = "text"


@dataclass
class ScanReport:
    """In-memory representation of a scan report, ready to serialize."""

    job_id: str
    target_path: str
    state: str
    started_at: str
    finished_at: Optional[str] = None
    files_total: int = 0
    files_scanned: int = 0
    files_clean: int = 0
    files_unknown: int = 0
    files_suspicious: int = 0
    files_malicious: int = 0
    files_skipped: int = 0
    results: List[Dict[str, Any]] = field(default_factory=list)
    threats: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "target_path": self.target_path,
            "state": self.state,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "files_total": self.files_total,
            "files_scanned": self.files_scanned,
            "files_clean": self.files_clean,
            "files_unknown": self.files_unknown,
            "files_suspicious": self.files_suspicious,
            "files_malicious": self.files_malicious,
            "files_skipped": self.files_skipped,
            "results": self.results,
            "threats": self.threats,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }


class ReportGenerator:
    """Builds reports from scan job data stored in the database."""

    def __init__(self, db: Database, reports_dir: str | Path) -> None:
        self._db = db
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def load_job(self, job_id: str) -> Optional[ScanReport]:
        """Build a :class:`ScanReport` from the database."""
        job = self._db.fetchone(
            "SELECT * FROM scan_jobs WHERE id=?", (job_id,)
        )
        if job is None:
            return None
        results = self._db.fetchall(
            "SELECT * FROM scan_results WHERE job_id=? ORDER BY id ASC",
            (job_id,),
        )
        results_list = [dict(r) for r in results]
        threats = [r for r in results_list if r.get("detection") in ("MALICIOUS", "SUSPICIOUS")]
        return ScanReport(
            job_id=job["id"],
            target_path=job["target_path"],
            state=job["state"],
            started_at=job["started_at"],
            finished_at=job["finished_at"],
            files_total=job["files_total"] or 0,
            files_scanned=job["files_scanned"] or 0,
            files_clean=job["files_clean"] or 0,
            files_unknown=job["files_unknown"] or 0,
            files_suspicious=job["files_suspicious"] or 0,
            files_malicious=job["files_malicious"] or 0,
            files_skipped=job["files_skipped"] or 0,
            results=results_list,
            threats=threats,
        )

    def generate(
        self,
        job_id: str,
        fmt: ReportFormat = ReportFormat.HTML,
        output_path: Optional[str | Path] = None,
    ) -> Path:
        """Generate a report for ``job_id`` in the requested format.

        Returns the path to the written report file.
        """
        report = self.load_job(job_id)
        if report is None:
            raise ValueError(f"No scan job found with id {job_id}")

        if output_path is None:
            ext = fmt.value
            output_path = self.reports_dir / f"report_{job_id[:8]}.{ext}"
        output_path = Path(output_path)

        if fmt == ReportFormat.HTML:
            content = self._render_html(report)
        elif fmt == ReportFormat.JSON:
            content = json.dumps(report.to_dict(), indent=2, default=str, ensure_ascii=False)
        elif fmt == ReportFormat.TEXT:
            content = self._render_text(report)
        else:
            raise ValueError(f"Unknown report format: {fmt}")

        output_path.write_text(content, encoding="utf-8")
        logger.info("Generated %s report: %s", fmt.value, output_path)
        return output_path

    def _render_html(self, report: ScanReport) -> str:
        """Self-contained HTML report with inline CSS."""
        verdict_color = {
            "CLEAN": "#16a34a",
            "UNKNOWN": "#6b7280",
            "SUSPICIOUS": "#d97706",
            "MALICIOUS": "#dc2626",
            "SKIPPED": "#9333ea",
        }
        rows_html = []
        for r in report.results:
            verdict = r.get("detection") or "UNKNOWN"
            color = verdict_color.get(verdict, "#6b7280")
            rows_html.append(
                "<tr>"
                f"<td>{html.escape(str(r.get('file_path','')))}</td>"
                f"<td>{html.escape(str(r.get('file_type','') or ''))}</td>"
                f"<td>{r.get('file_size','')}</td>"
                f"<td><code>{html.escape(str(r.get('sha256','') or '')[:16])}</code></td>"
                f'<td style="color:{color};font-weight:700;">{html.escape(verdict)}</td>'
                f"<td>{html.escape(str(r.get('reason','') or ''))}</td>"
                "</tr>"
            )

        threats_html = []
        for t in report.threats:
            verdict = t.get("detection") or "UNKNOWN"
            color = verdict_color.get(verdict, "#dc2626")
            threats_html.append(
                "<div class='threat'>"
                f"<div class='threat-path'>{html.escape(str(t.get('file_path','')))}</div>"
                f"<div class='threat-verdict' style='color:{color};'>{html.escape(verdict)}</div>"
                f"<div class='threat-reason'>{html.escape(str(t.get('reason','') or ''))}</div>"
                f"<div class='threat-hash'><code>SHA-256: {html.escape(str(t.get('sha256','') or '')[:32])}...</code></div>"
                "</div>"
            )
        threats_section = (
            "<h2>تهدیدات شناسایی‌شده</h2>" + "".join(threats_html)
            if threats_html else "<h2>تهدیدات شناسایی‌شده</h2><p>هیچ تهدیدی شناسایی نشد.</p>"
        )

        return f"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ITShield Report - {html.escape(report.job_id[:8])}</title>
<style>
  body {{
    font-family: 'Vazirmatn', 'Vazir', 'IRANSans', sans-serif;
    background: #f5f5f8;
    color: #1a1d2e;
    margin: 0;
    padding: 20px;
    line-height: 1.6;
  }}
  .container {{
    max-width: 1100px;
    margin: 0 auto;
    background: #ffffff;
    border-radius: 10px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.08);
    overflow: hidden;
  }}
  .header {{
    background: linear-gradient(135deg, #1a1d2e 0%, #2d3456 100%);
    color: #ffffff;
    padding: 24px 32px;
  }}
  .header h1 {{
    margin: 0 0 8px 0;
    font-size: 22px;
  }}
  .header .meta {{
    color: #b8bdce;
    font-size: 13px;
  }}
  .body {{
    padding: 24px 32px;
  }}
  .stats {{
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 12px;
    margin: 16px 0 24px 0;
  }}
  .stat {{
    background: #f4f4f8;
    border: 1px solid #e0e0e8;
    border-radius: 8px;
    padding: 14px;
    text-align: center;
  }}
  .stat .value {{
    font-size: 24px;
    font-weight: 700;
    margin: 4px 0;
  }}
  .stat .label {{
    font-size: 11px;
    color: #6b7280;
    text-transform: uppercase;
  }}
  h2 {{
    border-bottom: 2px solid #e0e0e8;
    padding-bottom: 8px;
    margin-top: 28px;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }}
  th {{
    background: #f4f4f8;
    text-align: right;
    padding: 10px;
    border-bottom: 2px solid #e0e0e8;
    font-weight: 600;
  }}
  td {{
    padding: 8px 10px;
    border-bottom: 1px solid #e8e8f0;
  }}
  tr:hover {{
    background: #fafafd;
  }}
  code {{
    font-family: 'Courier New', monospace;
    background: #f4f4f8;
    padding: 1px 4px;
    border-radius: 3px;
    font-size: 12px;
  }}
  .threat {{
    background: #fef2f2;
    border-right: 4px solid #dc2626;
    padding: 12px 16px;
    margin-bottom: 10px;
    border-radius: 4px;
  }}
  .threat-path {{
    font-weight: 600;
    word-break: break-all;
  }}
  .threat-verdict {{
    font-weight: 700;
    margin: 4px 0;
  }}
  .threat-reason {{
    font-size: 12px;
    color: #4b5563;
  }}
  .threat-hash {{
    font-size: 11px;
    color: #6b7280;
    margin-top: 4px;
  }}
  .footer {{
    background: #f4f4f8;
    color: #6b7280;
    padding: 12px 32px;
    font-size: 12px;
    border-top: 1px solid #e0e0e8;
  }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>گزارش اسکن ITShield Antivirus</h1>
    <div class="meta">
      شناسه اسکن: <code>{html.escape(report.job_id)}</code><br>
      هدف: <code>{html.escape(report.target_path)}</code><br>
      شروع: {html.escape(report.started_at)} | پایان: {html.escape(report.finished_at or '—')}
    </div>
  </div>
  <div class="body">
    <div class="stats">
      <div class="stat"><div class="label">کل فایل‌ها</div><div class="value">{report.files_total}</div></div>
      <div class="stat"><div class="label">اسکن‌شده</div><div class="value">{report.files_scanned}</div></div>
      <div class="stat"><div class="value" style="color:#16a34a;">{report.files_clean}</div><div class="label">سالم</div></div>
      <div class="stat"><div class="value" style="color:#d97706;">{report.files_suspicious}</div><div class="label">مشکوک</div></div>
      <div class="stat"><div class="value" style="color:#dc2626;">{report.files_malicious}</div><div class="label">مخرب</div></div>
      <div class="stat"><div class="value" style="color:#9333ea;">{report.files_skipped}</div><div class="label">رد شده</div></div>
    </div>

    {threats_section}

    <h2>نتایج کامل ({len(report.results)} فایل)</h2>
    <table>
      <thead>
        <tr>
          <th>مسیر فایل</th>
          <th>نوع</th>
          <th>حجم</th>
          <th>SHA-256</th>
          <th>Verdict</th>
          <th>دلیل</th>
        </tr>
      </thead>
      <tbody>
        {"".join(rows_html) if rows_html else "<tr><td colspan='6' style='text-align:center;color:#6b7280;'>بدون نتیجه</td></tr>"}
      </tbody>
    </table>
  </div>
  <div class="footer">
    تولید شده توسط ITShield Antivirus v0.6.0 در {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}
  </div>
</div>
</body>
</html>"""

    def _render_text(self, report: ScanReport) -> str:
        """Plain-text report for terminal / log consumption."""
        lines = [
            "=" * 70,
            "ITShield Antivirus - Scan Report",
            "=" * 70,
            f"Job ID      : {report.job_id}",
            f"Target      : {report.target_path}",
            f"State       : {report.state}",
            f"Started at  : {report.started_at}",
            f"Finished at : {report.finished_at or '—'}",
            "",
            "Summary",
            "-" * 70,
            f"  Files total    : {report.files_total}",
            f"  Files scanned  : {report.files_scanned}",
            f"  Files clean    : {report.files_clean}",
            f"  Files suspicious: {report.files_suspicious}",
            f"  Files malicious: {report.files_malicious}",
            f"  Files skipped  : {report.files_skipped}",
            "",
            "Threats",
            "-" * 70,
        ]
        if not report.threats:
            lines.append("  (no threats detected)")
        else:
            for t in report.threats:
                lines.append(
                    f"  [{t.get('detection','')}] {t.get('file_path','')}\n"
                    f"      reason: {t.get('reason','')}\n"
                    f"      sha256: {(t.get('sha256') or '')[:32]}..."
                )
        lines += [
            "",
            "Per-file results",
            "-" * 70,
        ]
        if not report.results:
            lines.append("  (no results)")
        else:
            for r in report.results:
                verdict = r.get("detection", "")
                lines.append(
                    f"  {verdict.ljust(10)} {r.get('file_path','')}"
                )
        lines += [
            "",
            "=" * 70,
        ]
        return "\n".join(lines)
