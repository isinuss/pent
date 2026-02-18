#!/usr/bin/env python3
"""
PENT Web Server - Browser-based UI for the penetration testing assistant.
"""

import sys
import os
import json
import threading
import uuid
from datetime import datetime
from io import StringIO

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, request, jsonify, send_file, send_from_directory
from flask_socketio import SocketIO, emit

from modules.recon import ReconModule
from modules.vuln_scanner import VulnScannerModule
from modules.web_tester import WebTesterModule
from modules.js_analyzer import JSAnalyzerModule
from modules.takeover import TakeoverModule
from modules.custom_checks import CustomChecksModule
from modules.reporter import ReporterModule
from modules.guide import METHODOLOGIES

from rich.console import Console

app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static",
)
app.config["SECRET_KEY"] = os.urandom(24).hex()
socketio = SocketIO(app, async_mode="gevent", cors_allowed_origins="*")

# In-memory storage for scan results
scans = {}


# ------------------------------------------------------------------
# Helper: Rich console that captures output and streams via SocketIO
# ------------------------------------------------------------------
class WebConsole(Console):
    """Console that captures output and sends it to the browser via WebSocket."""

    def __init__(self, scan_id: str):
        self._buffer = StringIO()
        super().__init__(file=self._buffer, force_terminal=True, width=120, color_system="truecolor")
        self.scan_id = scan_id

    def print(self, *args, **kwargs):
        self._buffer.truncate(0)
        self._buffer.seek(0)
        super().print(*args, **kwargs)
        text = self._buffer.getvalue()
        if text.strip():
            socketio.emit("scan_output", {
                "scan_id": self.scan_id,
                "text": text,
            })


def run_scan_thread(scan_id: str, scan_type: str, target: str, options: dict):
    """Run a scan in a background thread, streaming output to WebSocket."""
    console = WebConsole(scan_id)
    scans[scan_id]["status"] = "running"
    scans[scan_id]["started_at"] = datetime.now().isoformat()

    socketio.emit("scan_status", {"scan_id": scan_id, "status": "running"})

    findings = []
    try:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        url = target if target.startswith("http") else f"https://{target}"

        if scan_type == "recon":
            mod = ReconModule(console)
            passive = options.get("passive", False)
            findings = mod.run(target, passive_only=passive)

        elif scan_type == "vuln_scan":
            mod = VulnScannerModule(console)
            quick = options.get("quick", True)
            findings = mod.run(target, quick=quick)

        elif scan_type == "web_test":
            mod = WebTesterModule(console)
            full = options.get("full", False)
            findings = mod.run(url, full=full)

        elif scan_type == "js_analyze":
            mod = JSAnalyzerModule(console)
            findings = mod.analyze(url)

        elif scan_type == "takeover":
            recon_mod = ReconModule(console)
            subs = recon_mod.subdomain_enum(domain)
            if subs:
                mod = TakeoverModule(console)
                findings = mod.check_subdomains(subs[:50])

        elif scan_type == "checks":
            mod = CustomChecksModule(console)
            findings = mod.run_all_builtin(target)

        elif scan_type == "full_auto":
            # Run all modules in sequence
            socketio.emit("scan_output", {"scan_id": scan_id, "text": "\n=== Phase 1/6: Reconnaissance ===\n"})
            recon_mod = ReconModule(console)
            findings.extend(recon_mod.run(target))

            socketio.emit("scan_output", {"scan_id": scan_id, "text": "\n=== Phase 2/6: Vulnerability Scanning ===\n"})
            vuln_mod = VulnScannerModule(console)
            findings.extend(vuln_mod.run(target, quick=True))

            socketio.emit("scan_output", {"scan_id": scan_id, "text": "\n=== Phase 3/6: Web Application Testing ===\n"})
            web_mod = WebTesterModule(console)
            findings.extend(web_mod.run(url, full=True))

            socketio.emit("scan_output", {"scan_id": scan_id, "text": "\n=== Phase 4/6: JavaScript Analysis ===\n"})
            js_mod = JSAnalyzerModule(console)
            findings.extend(js_mod.analyze(url))

            socketio.emit("scan_output", {"scan_id": scan_id, "text": "\n=== Phase 5/6: Security Checks ===\n"})
            checks_mod = CustomChecksModule(console)
            findings.extend(checks_mod.run_all_builtin(target))

            socketio.emit("scan_output", {"scan_id": scan_id, "text": "\n=== Phase 6/6: Subdomain Takeover ===\n"})
            subs = recon_mod.subdomain_enum(domain)
            if subs:
                takeover_mod = TakeoverModule(console)
                findings.extend(takeover_mod.check_subdomains(subs[:50]))

        scans[scan_id]["status"] = "completed"
        scans[scan_id]["findings"] = findings
        scans[scan_id]["completed_at"] = datetime.now().isoformat()

    except Exception as e:
        scans[scan_id]["status"] = "error"
        scans[scan_id]["error"] = str(e)
        socketio.emit("scan_output", {"scan_id": scan_id, "text": f"\n[ERROR] {e}\n"})

    socketio.emit("scan_status", {
        "scan_id": scan_id,
        "status": scans[scan_id]["status"],
        "finding_count": len(findings),
    })


# ------------------------------------------------------------------
# Routes: Pages
# ------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan")
def scan_page():
    return render_template("scan.html")


@app.route("/results")
def results_page():
    return render_template("results.html")


@app.route("/results/<scan_id>")
def result_detail_page(scan_id):
    return render_template("result_detail.html", scan_id=scan_id)


@app.route("/guides")
def guides_page():
    return render_template("guides.html")


@app.route("/guides/<topic>")
def guide_detail_page(topic):
    guide = METHODOLOGIES.get(topic)
    if not guide:
        return "Guide not found", 404
    return render_template("guide_detail.html", topic=topic, guide=guide)


# ------------------------------------------------------------------
# Routes: API
# ------------------------------------------------------------------
@app.route("/api/scan/start", methods=["POST"])
def api_start_scan():
    data = request.json
    target = data.get("target", "").strip()
    scan_type = data.get("scan_type", "recon")
    options = data.get("options", {})

    if not target:
        return jsonify({"error": "Target is required"}), 400

    scan_id = str(uuid.uuid4())[:8]
    scans[scan_id] = {
        "id": scan_id,
        "target": target,
        "scan_type": scan_type,
        "options": options,
        "status": "queued",
        "findings": [],
        "created_at": datetime.now().isoformat(),
    }

    thread = threading.Thread(
        target=run_scan_thread,
        args=(scan_id, scan_type, target, options),
        daemon=True,
    )
    thread.start()

    return jsonify({"scan_id": scan_id, "status": "queued"})


@app.route("/api/scan/<scan_id>")
def api_scan_status(scan_id):
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(scan)


@app.route("/api/scans")
def api_list_scans():
    scan_list = []
    for s in scans.values():
        scan_list.append({
            "id": s["id"],
            "target": s["target"],
            "scan_type": s["scan_type"],
            "status": s["status"],
            "finding_count": len(s.get("findings", [])),
            "created_at": s.get("created_at", ""),
        })
    scan_list.sort(key=lambda x: x["created_at"], reverse=True)
    return jsonify(scan_list)


@app.route("/api/scan/<scan_id>/findings")
def api_scan_findings(scan_id):
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(scan.get("findings", []))


@app.route("/api/scan/<scan_id>/report/<fmt>")
def api_generate_report(scan_id, fmt):
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    if fmt not in ("md", "html", "json"):
        return jsonify({"error": "Invalid format. Use md, html, or json"}), 400

    console = Console(file=StringIO())
    reporter = ReporterModule(console)
    reporter.target = scan["target"]
    reporter.tester = "PENT Web UI"
    reporter.add_findings(scan.get("findings", []))

    output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
    filepath = reporter.run(output_dir=output_dir, fmt=fmt)

    mime_types = {"md": "text/markdown", "html": "text/html", "json": "application/json"}
    return send_file(filepath, mimetype=mime_types[fmt], as_attachment=True)


@app.route("/api/guides")
def api_list_guides():
    guides = []
    for key, data in METHODOLOGIES.items():
        guides.append({"key": key, "title": data["title"]})
    return jsonify(guides)


@app.route("/api/guides/<topic>")
def api_get_guide(topic):
    guide = METHODOLOGIES.get(topic)
    if not guide:
        return jsonify({"error": "Guide not found"}), 404
    return jsonify(guide)


# ------------------------------------------------------------------
# WebSocket events
# ------------------------------------------------------------------
@socketio.on("connect")
def handle_connect():
    emit("connected", {"status": "ok"})


@socketio.on("subscribe_scan")
def handle_subscribe(data):
    scan_id = data.get("scan_id")
    if scan_id and scan_id in scans:
        emit("scan_status", {
            "scan_id": scan_id,
            "status": scans[scan_id]["status"],
        })


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------
def main():
    import argparse
    parser = argparse.ArgumentParser(description="PENT Web Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()

    print(f"""
    ____  _______   ________
   / __ \\/ ____/ | / /_  __/
  / /_/ / __/ /  |/ / / /
 / ____/ /___/ /|  / / /
/_/   /_____/_/ |_/ /_/

  Web UI starting on http://{args.host}:{args.port}
  Open your browser and navigate to the URL above.
    """)

    socketio.run(app, host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
