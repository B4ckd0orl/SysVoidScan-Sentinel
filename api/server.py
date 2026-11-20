#!/usr/bin/env python3
"""
REST API Server for SysVoidScan v3.0 Sentinel.
Provides HTTP API for remote scanning, results retrieval, and management.
"""

import json
import os
import threading
import time
import uuid
from typing import Dict, List, Optional
from dataclasses import asdict

from core.finding import Finding, FindingType, FindingManager


def create_app():
    try:
        from flask import Flask, request, jsonify, abort
        from flask_cors import CORS
    except ImportError:
        raise ImportError("Flask and flask-cors are required: pip install flask flask-cors")

    app = Flask(__name__)
    CORS(app)
    scan_jobs: Dict[str, Dict] = {}
    finding_manager = FindingManager()

    @app.route("/api/v1/health", methods=["GET"])
    def health():
        return jsonify({
            "status": "healthy",
            "version": "3.0.0",
            "name": "SysVoidScan Sentinel",
        })

    @app.route("/api/v1/scan", methods=["POST"])
    def start_scan():
        data = request.get_json()
        if not data or "target" not in data:
            return jsonify({"error": "Missing 'target' parameter"}), 400
        job_id = str(uuid.uuid4())
        target = data["target"]
        scan_type = data.get("scan_type", "full")
        options = data.get("options", {})
        job = {
            "id": job_id,
            "target": target,
            "scan_type": scan_type,
            "options": options,
            "status": "queued",
            "started_at": time.time(),
            "findings": [],
            "error": None,
        }
        scan_jobs[job_id] = job
        thread = threading.Thread(target=_run_scan, args=(job_id, app), daemon=True)
        thread.start()
        return jsonify({"job_id": job_id, "status": "queued", "target": target})

    @app.route("/api/v1/scan/<job_id>", methods=["GET"])
    def get_scan(job_id):
        if job_id not in scan_jobs:
            return jsonify({"error": "Job not found"}), 404
        job = scan_jobs[job_id]
        return jsonify({
            "id": job["id"],
            "target": job["target"],
            "status": job["status"],
            "started_at": job["started_at"],
            "findings_count": len(job["findings"]),
            "error": job["error"],
        })

    @app.route("/api/v1/scan/<job_id>/results", methods=["GET"])
    def get_results(job_id):
        if job_id not in scan_jobs:
            return jsonify({"error": "Job not found"}), 404
        job = scan_jobs[job_id]
        format_type = request.args.get("format", "json")
        if format_type == "summary":
            summary = _summarize_findings(job["findings"])
            return jsonify(summary)
        return jsonify({
            "job_id": job_id,
            "target": job["target"],
            "status": job["status"],
            "findings": [_finding_to_dict(f) for f in job["findings"]],
        })

    @app.route("/api/v1/scan/<job_id>/report", methods=["GET"])
    def get_report(job_id):
        if job_id not in scan_jobs:
            return jsonify({"error": "Job not found"}), 404
        job = scan_jobs[job_id]
        report_format = request.args.get("format", "json")
        report = _generate_report(job, report_format)
        return jsonify({"report": report, "format": report_format})

    @app.route("/api/v1/scans", methods=["GET"])
    def list_scans():
        jobs = []
        for jid, job in scan_jobs.items():
            jobs.append({
                "id": jid,
                "target": job["target"],
                "status": job["status"],
                "started_at": job["started_at"],
                "findings_count": len(job["findings"]),
            })
        return jsonify({"scans": jobs})

    @app.route("/api/v1/findings", methods=["GET"])
    def list_findings():
        all_findings = []
        for job in scan_jobs.values():
            all_findings.extend(job["findings"])
        severity = request.args.get("severity")
        finding_type = request.args.get("type")
        if severity:
            all_findings = [f for f in all_findings if f.severity.lower() == severity.lower()]
        if finding_type:
            all_findings = [f for f in all_findings if (f.type.value if hasattr(f.type, "value") else str(f.type)) == finding_type]
        return jsonify({"findings": [_finding_to_dict(f) for f in all_findings], "total": len(all_findings)})

    @app.route("/api/v1/stats", methods=["GET"])
    def get_stats():
        all_findings = []
        for job in scan_jobs.values():
            all_findings.extend(job["findings"])
        return jsonify(_summarize_findings(all_findings))

    return app


def _finding_to_dict(finding: Finding) -> Dict:
    return {
        "url": finding.url,
        "severity": finding.severity,
        "title": finding.title,
        "description": finding.description,
        "finding_type": finding.type.value if hasattr(finding.type, "value") else str(finding.type),
        "parameter": finding.parameter,
        "evidence": finding.evidence,
        "cvss_score": finding.cvss_score,
        "cwe": finding.cwe,
        "remediation": finding.remediation,
        "exploitable": finding.exploitable,
        "references": finding.references_list,
    }


def _summarize_findings(findings: List[Finding]) -> Dict:
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    type_counts = {}
    for f in findings:
        sev = f.severity.lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
        ft = f.type.value if hasattr(f.type, "value") else str(f.type)
        type_counts[ft] = type_counts.get(ft, 0) + 1
    return {
        "total_findings": len(findings),
        "severity_distribution": severity_counts,
        "type_distribution": type_counts,
    }


def _generate_report(job: Dict, format: str) -> str:
    findings = job["findings"]
    summary = _summarize_findings(findings)
    if format == "text":
        lines = [f"Scan Report for {job['target']}", "=" * 50, f"Status: {job['status']}", f"Total Findings: {summary['total_findings']}", ""]
        lines.append("Severity Distribution:")
        for sev, count in summary["severity_distribution"].items():
            if count > 0:
                lines.append(f"  {sev.upper()}: {count}")
        lines.append("")
        for f in findings:
            lines.append(f"[{f.severity.upper()}] {f.title}")
            lines.append(f"  URL: {f.url}")
            if f.parameter:
                lines.append(f"  Parameter: {f.parameter}")
            lines.append("")
        return "\n".join(lines)
    return json.dumps(summary, indent=2)


def _run_scan(job_id: str, app):
    with app.app_context():
        job = scan_jobs[job_id]
        job["status"] = "running"
        try:
            from core.scanner import Scanner
            scanner = Scanner()
            # run the full pentest; scanner will populate its findings list
            scanner.run_full_pentest(job["target"])
            job["findings"] = getattr(scanner, "findings", []) or []
            job["status"] = "completed"
        except Exception as e:
            job["status"] = "failed"
            job["error"] = str(e)


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=8080, debug=False)
