from flask import Flask, request, send_from_directory, jsonify
from flask_cors import CORS
from zapv2 import ZAPv2
import subprocess
import os
import json
import time
import socket
import textwrap
from datetime import datetime, timezone
from fpdf import FPDF
from urllib.parse import urlparse
from os.path import basename

from pathlib import Path
from dotenv import load_dotenv

env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=env_path)

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "static", "dist")

SCAN_TYPES = {
    "passive": {
        "label": "Passive Scan",
        "description": "Quick and non-intrusive. Analyzes traffic without attacking the target.",
        "duration_hint": "~1 min",
        "zap_mode": "passive",
        "nmap_args": ["-F", "-T4"],
        "alert_limit": 10,
        "zap_timeout": 90,
    },
    "normal": {
        "label": "Normal Scan",
        "description": "Balanced coverage. Crawls the site with spider and detects service versions.",
        "duration_hint": "~3–5 min",
        "zap_mode": "spider",
        "nmap_args": ["-sV", "-T4"],
        "alert_limit": 25,
        "zap_timeout": 300,
    },
    "deep": {
        "label": "Deep Scan",
        "description": "Thorough assessment. Active attack simulation plus comprehensive port scanning.",
        "duration_hint": "~10–20 min",
        "zap_mode": "active",
        "nmap_args": ["-sV", "-sC", "-T4", "--top-ports", "1000"],
        "alert_limit": 50,
        "zap_timeout": 1200,
    },
}
DEFAULT_SCAN_TYPE = "passive"

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
CORS(app)

# -------------------------------
# ZAP CONFIG
# -------------------------------
ZAP_PROXY = os.environ.get("ZAP_PROXY", "http://localhost:8080")
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "94q9uk497obple5r0sliva2dmd")
zap = ZAPv2(
    apikey=ZAP_API_KEY,
    proxies={"http": ZAP_PROXY, "https": ZAP_PROXY},
)

# -------------------------------
# REPORT DIR
# -------------------------------
REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")


# -------------------------------
# SCAN HISTORY
# -------------------------------
def scan_json_path(scan_id):
    return os.path.join(REPORT_DIR, f"report_{scan_id}.json")


def save_scan_record(result):
    scan_id = result["id"]
    path = scan_json_path(scan_id)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    return path


def load_scan_record(scan_id):
    path = scan_json_path(scan_id)
    if not os.path.isfile(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def list_scan_records():
    records = []
    report_dir = Path(REPORT_DIR)

    for json_file in sorted(report_dir.glob("report_*.json"), reverse=True):
        try:
            with open(json_file, encoding="utf-8") as f:
                data = json.load(f)
            summary = data.get("summary", {})
            records.append(
                {
                    "id": data.get("id", json_file.stem.replace("report_", "")),
                    "url": data.get("url", ""),
                    "domain": data.get("domain", ""),
                    "scan_type": data.get("scan_type", DEFAULT_SCAN_TYPE),
                    "scan_label": data.get("scan_label", ""),
                    "created_at": data.get("created_at", ""),
                    "report_filename": data.get("report_filename", json_file.name),
                    "summary": summary,
                    "alert_total": sum(summary.values()),
                    "has_full_data": True,
                }
            )
        except (json.JSONDecodeError, OSError) as e:
            print(f"[History] Skipping {json_file}: {e}")

    json_stems = {r["id"] for r in records}
    for pdf_file in sorted(report_dir.glob("report_*.pdf"), reverse=True):
        scan_id = pdf_file.stem.replace("report_", "")
        if scan_id not in json_stems:
            ts = int(scan_id) if scan_id.isdigit() else 0
            created_at = (
                datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
                if ts
                else ""
            )
            records.append(
                {
                    "id": scan_id,
                    "url": "",
                    "domain": "",
                    "scan_type": "",
                    "scan_label": "Legacy Report",
                    "created_at": created_at,
                    "report_filename": pdf_file.name,
                    "summary": {},
                    "alert_total": 0,
                    "has_full_data": False,
                }
            )

    records.sort(key=lambda r: r.get("created_at", ""), reverse=True)
    return records


# -------------------------------
# TEXT CLEANER
# -------------------------------
def sanitize_text(text):
    if isinstance(text, str):
        return text.encode("latin-1", "replace").decode("latin-1")
    return text


def wrap_text(text, max_len=80):
    return "\n".join(textwrap.wrap(text, width=max_len, break_long_words=True))


def extract_domain(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    if ":" in domain:
        domain = domain.split(":")[0]
    return domain


def normalize_zap_alerts(alerts):
    normalized = []
    for alert in alerts:
        normalized.append(
            {
                "alert": alert.get("alert", "N/A"),
                "risk": alert.get("risk", "N/A"),
                "url": alert.get("url", ""),
                "description": alert.get("description", ""),
                "solution": alert.get("solution", ""),
            }
        )
    return normalized


def count_alerts_by_risk(zap_alerts):
    risks = ["High", "Medium", "Low", "Informational"]
    return {risk: sum(1 for a in zap_alerts if a.get("risk") == risk) for risk in risks}


# -------------------------------
# NMAP SCAN
# -------------------------------
def run_nmap_scan(domain, nmap_args=None):
    args = nmap_args or SCAN_TYPES[DEFAULT_SCAN_TYPE]["nmap_args"]
    try:
        ip = socket.gethostbyname(domain)
        print(f"[+] Nmap scan on {domain} ({ip}) with args: {args}")

        result = subprocess.check_output(["nmap", *args, ip], text=True, timeout=900)
        return result

    except subprocess.TimeoutExpired:
        return "[Nmap Error] Scan timed out"
    except Exception as e:
        return f"[Nmap Error] {str(e)}"


# -------------------------------
# ZAP HELPERS
# -------------------------------
def _wait_zap_passive(timeout):
    start = time.time()
    while int(zap.pscan.records_to_scan) > 0:
        if time.time() - start > timeout:
            print("[ZAP] Passive scan timeout reached")
            break
        time.sleep(2)


def _run_zap_spider(url, timeout):
    print(f"[ZAP] Spider scan on {url}")
    try:
        scan_id = zap.spider.scan(url)
        start = time.time()
        while int(zap.spider.status(scan_id)) < 100:
            if time.time() - start > timeout:
                print("[ZAP] Spider scan timeout reached")
                zap.spider.stop(scan_id)
                break
            time.sleep(2)
        return True
    except Exception as e:
        print(f"[ZAP] Spider error: {e}")
        return False


def _run_zap_active(url, timeout):
    print(f"[ZAP] Active scan on {url}")
    try:
        scan_id = zap.ascan.scan(url)
        start = time.time()
        while int(zap.ascan.status(scan_id)) < 100:
            if time.time() - start > timeout:
                print("[ZAP] Active scan timeout reached")
                zap.ascan.stop(scan_id)
                break
            time.sleep(5)
        return True
    except Exception as e:
        print(f"[ZAP] Active scan error: {e}")
        return False


def run_zap_scan(url, scan_config):
    mode = scan_config["zap_mode"]
    timeout = scan_config["zap_timeout"]
    alert_limit = scan_config["alert_limit"]
    steps = []

    print(f"[ZAP] Starting {mode} scan on {url}")

    try:
        if mode == "passive":
            zap.urlopen(url)
            steps.append("Loaded target through ZAP proxy")
            time.sleep(5)
            _wait_zap_passive(timeout)
            steps.append("Completed passive analysis")

        elif mode == "spider":
            if _run_zap_spider(url, timeout):
                steps.append("Spider crawl completed")
            try:
                zap.urlopen(url)
            except Exception:
                pass
            _wait_zap_passive(min(timeout, 120))
            steps.append("Passive analysis on crawled pages")

        elif mode == "active":
            if _run_zap_spider(url, min(timeout // 3, 300)):
                steps.append("Spider crawl completed")
            if _run_zap_active(url, timeout):
                steps.append("Active scan completed")
            _wait_zap_passive(min(timeout // 4, 180))
            steps.append("Passive analysis completed")

        alerts = zap.core.alerts(baseurl=url)
        return alerts[:alert_limit], steps, None

    except Exception as e:
        print(f"[ZAP] Scan error: {e}")
        return [], steps, str(e)


# -------------------------------
# FIX SUGGESTIONS
# -------------------------------
def get_fix_suggestion(risk):
    fixes = {
        "high": "Fix immediately. Critical risk.",
        "medium": "Apply validation and security headers.",
        "low": "Review configuration.",
        "informational": "No action required.",
    }
    return fixes.get(risk.lower(), "Review manually.")


# -------------------------------
# GEMINI ANALYSIS
# -------------------------------
def analyze_with_gemini(zap_alerts, nmap_output, url, scan_type="passive"):
    scan_label = SCAN_TYPES.get(scan_type, {}).get("label", scan_type)
    if not GEMINI_API_KEY:
        return {
            "available": False,
            "analysis": "",
            "message": "Gemini API key not configured. Set GEMINI_API_KEY in your environment.",
        }

    try:
        import google.generativeai as genai

        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel("gemini-2.0-flash")

        if zap_alerts:
            alerts_text = "\n".join(
                f"- {a['alert']} ({a['risk']}): {a.get('description', '')[:300]}"
                for a in zap_alerts
            )
        else:
            alerts_text = "No ZAP alerts detected."

        prompt = f"""You are a senior application security engineer. Analyze these VAPT scan results for {url}.

Scan Type: {scan_label}

ZAP Vulnerability Alerts:
{alerts_text}

Nmap Port Scan Output:
{nmap_output}

Provide a concise security analysis with these sections:
1. **Executive Summary** — 2-3 sentences on overall security posture
2. **Risk Level** — Overall rating (Critical/High/Medium/Low) with brief justification
3. **Key Vulnerabilities** — Bullet list of the most important findings from ZAP
4. **Network Exposure** — Analysis of open ports and services from nmap
5. **Prioritized Recommendations** — Numbered action items ordered by urgency

Use clear markdown formatting. Be specific and actionable."""

        response = model.generate_content(prompt)
        analysis_text = response.text if response.text else "No analysis returned."

        return {"available": True, "analysis": analysis_text, "message": ""}

    except Exception as e:
        print(f"[Gemini] Analysis error: {e}")
        return {
            "available": False,
            "analysis": "",
            "message": f"Gemini analysis failed: {str(e)}",
        }


# -------------------------------
# PDF REPORT
# -------------------------------
def generate_pdf_report(
    zap_alerts, nmap_output, gemini_analysis="", scan_type="passive", scan_id=None
):
    scan_label = SCAN_TYPES.get(scan_type, {}).get("label", scan_type)
    scan_id = scan_id or str(int(time.time()))
    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Helvetica", size=14)
    pdf.cell(0, 10, text="VAPT Report", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(3)

    pdf.set_font("Helvetica", size=10)
    pdf.cell(
        0, 8, text=f"Scan Type: {scan_label}", new_x="LMARGIN", new_y="NEXT"
    )
    pdf.ln(3)

    pdf.cell(0, 8, text="Top Vulnerabilities:", new_x="LMARGIN", new_y="NEXT")

    if not zap_alerts:
        pdf.cell(
            0,
            8,
            text="No major vulnerabilities found.",
            new_x="LMARGIN",
            new_y="NEXT",
        )

    for alert in zap_alerts:
        name = alert.get("alert", "N/A")
        risk = alert.get("risk", "N/A")
        fix = get_fix_suggestion(risk)

        safe_text = wrap_text(f"- {name} ({risk})")
        safe_fix = wrap_text(f"Fix: {fix}")

        pdf.multi_cell(
            0, 6, text=sanitize_text(safe_text), new_x="LMARGIN", new_y="NEXT"
        )
        pdf.multi_cell(
            0, 6, text=sanitize_text(safe_fix), new_x="LMARGIN", new_y="NEXT"
        )
        pdf.ln(1)

    pdf.ln(3)
    pdf.cell(0, 8, text="Nmap Summary:", new_x="LMARGIN", new_y="NEXT")

    short_nmap = "\n".join(nmap_output.split("\n")[:15])
    pdf.multi_cell(
        0,
        6,
        text=sanitize_text(wrap_text(short_nmap, 100)),
        new_x="LMARGIN",
        new_y="NEXT",
    )

    if gemini_analysis:
        pdf.ln(3)
        pdf.cell(0, 8, text="AI Security Analysis:", new_x="LMARGIN", new_y="NEXT")
        short_analysis = gemini_analysis[:2000]
        pdf.multi_cell(
            0,
            6,
            text=sanitize_text(wrap_text(short_analysis, 100)),
            new_x="LMARGIN",
            new_y="NEXT",
        )

    filename = os.path.join(REPORT_DIR, f"report_{scan_id}.pdf")
    pdf.output(filename)

    return filename, scan_id


# -------------------------------
# SCAN ORCHESTRATION
# -------------------------------
def get_scan_config(scan_type):
    if scan_type not in SCAN_TYPES:
        return None
    return SCAN_TYPES[scan_type]


def run_full_scan(url, scan_type=DEFAULT_SCAN_TYPE):
    scan_config = get_scan_config(scan_type)
    if not scan_config:
        return None, f"Invalid scan type. Choose: {', '.join(SCAN_TYPES)}"

    domain = extract_domain(url)
    if not domain:
        return None, "Invalid URL"

    raw_alerts, zap_steps, zap_error = run_zap_scan(url, scan_config)
    zap_alerts = normalize_zap_alerts(raw_alerts)
    nmap_output = run_nmap_scan(domain, scan_config["nmap_args"])

    gemini_result = analyze_with_gemini(
        zap_alerts, nmap_output, url, scan_type=scan_type
    )
    gemini_analysis = gemini_result.get("analysis", "")

    scan_id = str(int(time.time()))
    report_path, scan_id = generate_pdf_report(
        zap_alerts,
        nmap_output,
        gemini_analysis,
        scan_type=scan_type,
        scan_id=scan_id,
    )
    report_filename = basename(report_path)

    result = {
        "id": scan_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "url": url,
        "domain": domain,
        "scan_type": scan_type,
        "scan_label": scan_config["label"],
        "scan_description": scan_config["description"],
        "zap_alerts": zap_alerts,
        "nmap_output": nmap_output,
        "report_filename": report_filename,
        "summary": count_alerts_by_risk(zap_alerts),
        "gemini": gemini_result,
        "scan_meta": {
            "zap_mode": scan_config["zap_mode"],
            "nmap_args": scan_config["nmap_args"],
            "zap_steps": zap_steps,
            "zap_error": zap_error,
        },
    }

    save_scan_record(result)
    return result, None


# -------------------------------
# API ROUTES
# -------------------------------
@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or request.form.get("url") or "").strip()
    scan_type = (
        data.get("scan_type") or request.form.get("scan_type") or DEFAULT_SCAN_TYPE
    ).strip().lower()

    if not url:
        return jsonify({"error": "Enter valid URL"}), 400

    result, error = run_full_scan(url, scan_type=scan_type)
    if error:
        return jsonify({"error": error}), 400

    return jsonify(result)


@app.route("/api/reports", methods=["GET"])
def api_list_reports():
    return jsonify({"reports": list_scan_records()})


@app.route("/api/reports/<scan_id>", methods=["GET"])
def api_get_report(scan_id):
    record = load_scan_record(scan_id)
    if not record:
        pdf_path = os.path.join(REPORT_DIR, f"report_{scan_id}.pdf")
        if os.path.isfile(pdf_path):
            return jsonify(
                {
                    "error": "Full scan data unavailable. Only PDF download exists for this report.",
                    "id": scan_id,
                    "report_filename": f"report_{scan_id}.pdf",
                    "has_full_data": False,
                }
            ), 404
        return jsonify({"error": "Report not found"}), 404
    return jsonify(record)


@app.route("/api/scan-types", methods=["GET"])
def api_scan_types():
    types = {}
    for key, cfg in SCAN_TYPES.items():
        types[key] = {
            "label": cfg["label"],
            "description": cfg["description"],
            "duration_hint": cfg["duration_hint"],
            "zap_mode": cfg["zap_mode"],
        }
    return jsonify({"scan_types": types, "default": DEFAULT_SCAN_TYPE})


@app.route("/api/health", methods=["GET"])
def api_health():
    return jsonify(
        {
            "status": "ok",
            "gemini_configured": bool(GEMINI_API_KEY),
            "scan_types": list(SCAN_TYPES.keys()),
        }
    )


# -------------------------------
# DOWNLOAD ROUTE
# -------------------------------
@app.route("/download/<filename>")
def download_report(filename):
    return send_from_directory(REPORT_DIR, filename, as_attachment=True)


# -------------------------------
# REACT FRONTEND
# -------------------------------
@app.route("/")
def serve_index():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        return send_from_directory(FRONTEND_DIR, "index.html")
    return (
        jsonify(
            {
                "error": "Frontend not built. Run: cd frontend && npm install && npm run build"
            }
        ),
        503,
    )


@app.route("/assets/<path:filename>")
def serve_assets(filename):
    assets_dir = os.path.join(FRONTEND_DIR, "assets")
    return send_from_directory(assets_dir, filename)


# -------------------------------
# RUN APP
# -------------------------------
if __name__ == "__main__":
    app.run(debug=False, use_reloader=False)
