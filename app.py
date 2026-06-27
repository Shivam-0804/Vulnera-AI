from flask import Flask, request, send_from_directory, jsonify
from flask_cors import CORS
from zapv2 import ZAPv2
from concurrent.futures import ThreadPoolExecutor, as_completed
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
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(dotenv_path=BASE_DIR / ".env")

FRONTEND_DIR = BASE_DIR / "static" / "dist"
REPORT_DIR = BASE_DIR / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

SCAN_TYPES = {
    "passive": {
        "label": "Passive Scan",
        "description": "Quick and non-intrusive. Analyzes traffic without attacking the target.",
        "duration_hint": "~1 min",
        "zap_mode": "passive",
        "nmap_args": ["-Pn", "-F", "-T4"],
        "alert_limit": 10,
        "zap_timeout": 90,
    },
    "normal": {
        "label": "Normal Scan",
        "description": "Balanced coverage. Crawls the site with spider and detects service versions.",
        "duration_hint": "~3–5 min",
        "zap_mode": "spider",
        "nmap_args": ["-Pn", "-sV", "-T4"],
        "alert_limit": 25,
        "zap_timeout": 300,
    },
    "deep": {
        "label": "Deep Scan",
        "description": "Thorough assessment. Active attack simulation plus comprehensive port scanning.",
        "duration_hint": "~10–20 min",
        "zap_mode": "active",
        "nmap_args": ["-Pn", "-sV", "-sC", "-T4", "--top-ports", "1000"],
        "alert_limit": 50,
        "zap_timeout": 1200,
    },
}
DEFAULT_SCAN_TYPE = "passive"
AI_PROVIDER = os.environ.get("AI_PROVIDER", "").strip().lower()
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen3:8b").strip()
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash").strip()
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()
ZAP_PROXY = os.environ.get("ZAP_PROXY", "http://localhost:8080").strip()
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "").strip()

app = Flask(__name__, static_folder=str(FRONTEND_DIR), static_url_path="")
CORS(app)

zap = ZAPv2(
    apikey=ZAP_API_KEY,
    proxies={"http": ZAP_PROXY, "https": ZAP_PROXY},
)


def sanitize_text(text):
    if isinstance(text, str):
        return text.encode("latin-1", "replace").decode("latin-1")
    return text


def wrap_text(text, max_len=80):
    return "\n".join(textwrap.wrap(str(text), width=max_len, break_long_words=True))


def normalize_url(url):
    url = (url or "").strip()
    if not url:
        return ""
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
        parsed = urlparse(url)
    if not parsed.netloc:
        return ""
    return url


def extract_domain(url):
    parsed = urlparse(url)
    domain = parsed.hostname or parsed.netloc or ""
    if domain and ":" in domain:
        domain = domain.split(":")[0]
    return domain


def normalize_zap_alerts(alerts):
    normalized = []
    for alert in alerts or []:
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


def scan_json_path(scan_id):
    return REPORT_DIR / f"report_{scan_id}.json"


def save_scan_record(result):
    path = scan_json_path(result["id"])
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    return str(path)


def load_scan_record(scan_id):
    path = scan_json_path(scan_id)
    if not path.is_file():
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def list_scan_records():
    records = []
    json_stems = set()
    for json_file in sorted(REPORT_DIR.glob("report_*.json"), reverse=True):
        try:
            with open(json_file, encoding="utf-8") as f:
                data = json.load(f)
            summary = data.get("summary", {})
            scan_id = data.get("id", json_file.stem.replace("report_", ""))
            json_stems.add(scan_id)
            records.append(
                {
                    "id": scan_id,
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
        except (json.JSONDecodeError, OSError):
            pass
    for pdf_file in sorted(REPORT_DIR.glob("report_*.pdf"), reverse=True):
        scan_id = pdf_file.stem.replace("report_", "")
        if scan_id not in json_stems:
            ts = int(scan_id) if scan_id.isdigit() else 0
            created_at = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else ""
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


def get_fix_suggestion(risk):
    fixes = {
        "high": "Fix immediately. Critical risk.",
        "medium": "Apply validation and security headers.",
        "low": "Review configuration.",
        "informational": "No action required.",
    }
    return fixes.get(str(risk).lower(), "Review manually.")


def run_nmap_scan(domain, nmap_args=None):
    args = nmap_args or SCAN_TYPES[DEFAULT_SCAN_TYPE]["nmap_args"]
    try:
        target = domain.strip()
        if not target:
            return "[Nmap Error] Invalid target"
        print(f"[+] Nmap scan on {target} with args: {args}")
        result = subprocess.run(
            ["nmap", *args, target],
            capture_output=True,
            text=True,
            timeout=900,
        )
        output = (result.stdout or "").strip()
        error = (result.stderr or "").strip()
        if output:
            return output
        if error:
            return error
        return "[Nmap] No output returned"
    except subprocess.TimeoutExpired:
        return "[Nmap Error] Scan timed out"
    except Exception as e:
        return f"[Nmap Error] {str(e)}"


def _new_zap_session():
    session_name = f"scan_{int(time.time())}"
    try:
        zap.core.new_session(session_name, True)
    except Exception:
        try:
            zap.core.new_session(session_name)
        except Exception:
            pass
    try:
        zap.core.delete_all_alerts()
    except Exception:
        pass


def _wait_until_done(get_status, scan_id, timeout, label, interval=2):
    start = time.time()
    last = None
    while True:
        try:
            status = int(get_status(scan_id))
        except Exception:
            return False
        if status >= 100:
            return True
        if status != last:
            print(f"[ZAP] {label} status: {status}%")
            last = status
        if time.time() - start > timeout:
            print(f"[ZAP] {label} timeout reached")
            return False
        time.sleep(interval)


def _wait_for_passive(timeout):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            remaining = int(zap.pscan.records_to_scan)
        except Exception:
            remaining = 0
        if remaining != last:
            print(f"[ZAP] Passive queue: {remaining}")
            last = remaining
        if remaining <= 0:
            break
        time.sleep(2)


def _run_zap_spider(url, timeout):
    print(f"[ZAP] Spider scan on {url}")
    try:
        scan_id = zap.spider.scan(url)
        if not scan_id:
            return False
        return _wait_until_done(zap.spider.status, scan_id, timeout, "Spider", 2)
    except Exception as e:
        print(f"[ZAP] Spider error: {e}")
        return False


def _run_zap_active(url, timeout):
    print(f"[ZAP] Active scan on {url}")
    try:
        scan_id = zap.ascan.scan(url)
        if not scan_id:
            return False
        return _wait_until_done(zap.ascan.status, scan_id, timeout, "Active scan", 5)
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
        _new_zap_session()
        try:
            zap.urlopen(url)
            steps.append("Loaded target through ZAP")
        except Exception as e:
            steps.append(f"Load failed: {str(e)}")
        if mode == "passive":
            _wait_for_passive(min(timeout, 20))
            time.sleep(3)
            steps.append("Passive processing finished")
        elif mode == "spider":
            spider_ok = _run_zap_spider(url, min(timeout, 180))
            steps.append("Spider crawl completed" if spider_ok else "Spider crawl timed out")
            _wait_for_passive(min(timeout, 45))
            steps.append("Passive analysis on crawled pages")
        elif mode == "active":
            spider_ok = _run_zap_spider(url, min(timeout // 3, 300))
            steps.append("Spider crawl completed" if spider_ok else "Spider crawl timed out")
            active_ok = _run_zap_active(url, min(timeout, 600))
            steps.append("Active scan completed" if active_ok else "Active scan timed out")
            _wait_for_passive(min(timeout, 90))
            steps.append("Passive analysis completed")
        try:
            alerts = zap.core.alerts(baseurl=url)
        except Exception:
            alerts = []
        if not alerts:
            try:
                alerts = zap.core.alerts()
            except Exception:
                alerts = []
        return alerts[:alert_limit], steps, None
    except Exception as e:
        print(f"[ZAP] Scan error: {e}")
        return [], steps, str(e)


def extract_nmap_open_lines(nmap_output, limit=8):
    lines = []
    for line in str(nmap_output).splitlines():
        if "open" in line.lower() and "/tcp" in line.lower():
            lines.append(line.strip())
    return lines[:limit]


def build_local_analysis(zap_alerts, nmap_output, url, scan_type):
    counts = count_alerts_by_risk(zap_alerts)
    total = sum(counts.values())
    open_lines = extract_nmap_open_lines(nmap_output)
    top_alerts = zap_alerts[:5]
    if counts["High"] > 0:
        risk_level = "High"
    elif counts["Medium"] > 0:
        risk_level = "Medium"
    elif total > 0:
        risk_level = "Low"
    else:
        risk_level = "Informational"
    summary = []
    summary.append(f"## Executive Summary\nThe {scan_type} scan for {url} completed successfully. The overall risk level is {risk_level.lower()}. {total} alerts were collected from ZAP.")
    summary.append(f"## Risk Level\nOverall Rating: {risk_level}\nHigh: {counts['High']} | Medium: {counts['Medium']} | Low: {counts['Low']} | Informational: {counts['Informational']}")
    if top_alerts:
        vuln_lines = []
        for alert in top_alerts:
            vuln_lines.append(f"- {alert.get('alert', 'N/A')} ({alert.get('risk', 'N/A')}): {alert.get('description', '')[:220]}")
        summary.append("## Key Vulnerabilities\n" + "\n".join(vuln_lines))
    else:
        summary.append("## Key Vulnerabilities\n- No ZAP alerts were returned during this scan.")
    if open_lines:
        summary.append("## Network Exposure\n" + "\n".join(f"- {line}" for line in open_lines))
    else:
        summary.append("## Network Exposure\n- No open TCP ports were reported by Nmap or the target filtered the scan.")
    recommendations = [
        "1. Fix all high-risk findings first.",
        "2. Review medium-risk findings and add input validation, authentication, and security headers.",
        "3. Retest after remediation to confirm the issue is resolved.",
        "4. Reduce exposed services and close unnecessary ports.",
    ]
    summary.append("## Prioritized Recommendations\n" + "\n".join(recommendations))
    return "\n\n".join(summary)


def _ollama_generate(prompt, model):
    payload = json.dumps({"model": model, "prompt": prompt, "stream": False}).encode("utf-8")
    req = Request("http://localhost:11434/api/generate", data=payload, headers={"Content-Type": "application/json"})
    with urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read().decode("utf-8", errors="replace"))
    return (data.get("response") or "").strip()


def _gemini_generate(prompt):
    if not GEMINI_API_KEY:
        return ""
    try:
        from google import genai
        client = genai.Client(api_key=GEMINI_API_KEY)
        response = client.models.generate_content(model=GEMINI_MODEL, contents=prompt)
        text = getattr(response, "text", "") or ""
        return text.strip()
    except Exception:
        pass
    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(GEMINI_MODEL)
        response = model.generate_content(prompt)
        text = getattr(response, "text", "") or ""
        return text.strip()
    except Exception:
        return ""


def analyze_with_ai(zap_alerts, nmap_output, url, scan_type="passive"):
    scan_label = SCAN_TYPES.get(scan_type, {}).get("label", scan_type)
    if zap_alerts:
        alerts_text = "\n".join(
            f"- {a['alert']} ({a['risk']}): {a.get('description', '')[:300]}"
            for a in zap_alerts
        )
    else:
        alerts_text = "No ZAP alerts detected."
    prompt = f"""You are a senior application security engineer. Analyze these VAPT scan results for {url}.\n\nScan Type: {scan_label}\n\nZAP Vulnerability Alerts:\n{alerts_text}\n\nNmap Port Scan Output:\n{nmap_output}\n\nProvide a concise security analysis with these sections:\n1. Executive Summary\n2. Risk Level\n3. Key Vulnerabilities\n4. Network Exposure\n5. Prioritized Recommendations\n\nUse clear markdown formatting. Be specific and actionable."""
    provider_order = []
    if AI_PROVIDER == "ollama":
        provider_order = ["ollama"]
    elif AI_PROVIDER == "gemini":
        provider_order = ["gemini"]
    else:
        provider_order = ["ollama", "gemini"]
    errors = []
    for provider in provider_order:
        try:
            if provider == "ollama":
                analysis_text = _ollama_generate(prompt, OLLAMA_MODEL)
                if analysis_text:
                    return {"available": True, "analysis": analysis_text, "message": "", "provider": "ollama"}
            elif provider == "gemini":
                analysis_text = _gemini_generate(prompt)
                if analysis_text:
                    return {"available": True, "analysis": analysis_text, "message": "", "provider": "gemini"}
        except Exception as e:
            errors.append(str(e))
    return {
        "available": False,
        "analysis": build_local_analysis(zap_alerts, nmap_output, url, scan_type),
        "message": " | ".join(errors) if errors else "Using local analysis fallback.",
        "provider": "local",
    }


def generate_pdf_report(zap_alerts, nmap_output, ai_analysis="", scan_type="passive", scan_id=None):
    scan_label = SCAN_TYPES.get(scan_type, {}).get("label", scan_type)
    scan_id = scan_id or str(int(time.time()))
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=14)
    pdf.cell(0, 10, text="VAPT Report", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(3)
    pdf.set_font("Helvetica", size=10)
    pdf.cell(0, 8, text=f"Scan Type: {scan_label}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)
    pdf.cell(0, 8, text="Top Vulnerabilities:", new_x="LMARGIN", new_y="NEXT")
    if not zap_alerts:
        pdf.cell(0, 8, text="No major vulnerabilities found.", new_x="LMARGIN", new_y="NEXT")
    for alert in zap_alerts:
        name = alert.get("alert", "N/A")
        risk = alert.get("risk", "N/A")
        fix = get_fix_suggestion(risk)
        pdf.multi_cell(0, 6, text=sanitize_text(wrap_text(f"- {name} ({risk})")), new_x="LMARGIN", new_y="NEXT")
        pdf.multi_cell(0, 6, text=sanitize_text(wrap_text(f"Fix: {fix}")), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)
    pdf.ln(3)
    pdf.cell(0, 8, text="Nmap Summary:", new_x="LMARGIN", new_y="NEXT")
    short_nmap = "\n".join(str(nmap_output).split("\n")[:15])
    pdf.multi_cell(0, 6, text=sanitize_text(wrap_text(short_nmap, 100)), new_x="LMARGIN", new_y="NEXT")
    if ai_analysis:
        pdf.ln(3)
        pdf.cell(0, 8, text="AI Security Analysis:", new_x="LMARGIN", new_y="NEXT")
        short_analysis = ai_analysis[:3000]
        pdf.multi_cell(0, 6, text=sanitize_text(wrap_text(short_analysis, 100)), new_x="LMARGIN", new_y="NEXT")
    filename = REPORT_DIR / f"report_{scan_id}.pdf"
    pdf.output(str(filename))
    return str(filename), scan_id


def get_scan_config(scan_type):
    return SCAN_TYPES.get(scan_type)


def run_full_scan(url, scan_type=DEFAULT_SCAN_TYPE):
    url = normalize_url(url)
    if not url:
        return None, "Invalid URL"
    scan_type = (scan_type or DEFAULT_SCAN_TYPE).strip().lower()
    scan_config = get_scan_config(scan_type)
    if not scan_config:
        return None, f"Invalid scan type. Choose: {', '.join(SCAN_TYPES)}"
    domain = extract_domain(url)
    if not domain:
        return None, "Invalid URL"
    scan_start = time.time()
    zap_steps = []
    zap_error = None
    raw_alerts = []
    nmap_output = ""
    print(f"[Scan] Running ZAP and Nmap in parallel for {url}")
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="scan") as executor:
        futures = {
            executor.submit(run_zap_scan, url, scan_config): "zap",
            executor.submit(run_nmap_scan, domain, scan_config["nmap_args"]): "nmap",
        }
        for future in as_completed(futures):
            task = futures[future]
            try:
                if task == "zap":
                    raw_alerts, zap_steps, zap_error = future.result()
                else:
                    nmap_output = future.result()
            except Exception as e:
                if task == "zap":
                    zap_error = str(e)
                else:
                    nmap_output = f"[Nmap Error] {str(e)}"
    parallel_elapsed = round(time.time() - scan_start, 1)
    print(f"[Scan] Parallel phase completed in {parallel_elapsed}s")
    zap_alerts = normalize_zap_alerts(raw_alerts)
    ai_result = analyze_with_ai(zap_alerts, nmap_output, url, scan_type=scan_type)
    ai_analysis = ai_result.get("analysis", "")
    scan_id = str(int(time.time()))
    report_path, scan_id = generate_pdf_report(zap_alerts, nmap_output, ai_analysis, scan_type=scan_type, scan_id=scan_id)
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
        "report_filename": basename(report_path),
        "summary": count_alerts_by_risk(zap_alerts),
        "ai": ai_result,
        "scan_meta": {
            "zap_mode": scan_config["zap_mode"],
            "nmap_args": scan_config["nmap_args"],
            "zap_steps": zap_steps,
            "zap_error": zap_error,
            "parallel_scan_seconds": parallel_elapsed,
        },
    }
    save_scan_record(result)
    return result, None


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or request.form.get("url") or "").strip()
    scan_type = (data.get("scan_type") or request.form.get("scan_type") or DEFAULT_SCAN_TYPE).strip().lower()
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
        pdf_path = REPORT_DIR / f"report_{scan_id}.pdf"
        if pdf_path.is_file():
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
            "zap_connected": True,
            "ai_provider": AI_PROVIDER or "auto",
            "ollama_model": OLLAMA_MODEL,
            "gemini_configured": bool(GEMINI_API_KEY),
            "scan_types": list(SCAN_TYPES.keys()),
        }
    )


@app.route("/download/<filename>")
def download_report(filename):
    return send_from_directory(REPORT_DIR, filename, as_attachment=True)


@app.route("/view/<filename>")
def view_report(filename):
    return send_from_directory(REPORT_DIR, filename, as_attachment=False, mimetype="application/pdf")


@app.route("/")
def serve_index():
    index_path = FRONTEND_DIR / "index.html"
    if index_path.exists():
        return send_from_directory(str(FRONTEND_DIR), "index.html")
    return jsonify({"error": "Frontend not built. Run: cd frontend && npm install && npm run build"}), 503


@app.route("/assets/<path:filename>")
def serve_assets(filename):
    assets_dir = FRONTEND_DIR / "assets"
    return send_from_directory(str(assets_dir), filename)


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False,
        use_reloader=False,
    )
