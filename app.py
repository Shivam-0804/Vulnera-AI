from flask import Flask, request, send_from_directory, jsonify
from flask_cors import CORS
from zapv2 import ZAPv2
import subprocess
import os
import time
import socket
import textwrap
from fpdf import FPDF
from urllib.parse import urlparse
from os.path import basename
from dotenv import load_dotenv

load_dotenv()

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "static", "dist")

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
# NMAP SCAN (FAST)
# -------------------------------
def run_nmap_scan(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"[+] Nmap scan on {domain} ({ip})")

        result = subprocess.check_output(["nmap", "-F", "-T4", ip], text=True)
        return result

    except Exception as e:
        return f"[Nmap Error] {str(e)}"


# -------------------------------
# ZAP PASSIVE SCAN (FAST)
# -------------------------------
def zap_passive_scan(url):
    print(f"[ZAP] Scanning {url}")

    try:
        zap.urlopen(url)
    except Exception:
        return []

    time.sleep(5)

    timeout = 60
    start = time.time()

    while int(zap.pscan.records_to_scan) > 0:
        if time.time() - start > timeout:
            print("[ZAP] Timeout reached")
            break
        time.sleep(2)

    alerts = zap.core.alerts(baseurl=url)
    return alerts[:10]


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
def analyze_with_gemini(zap_alerts, nmap_output, url):
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
def generate_pdf_report(zap_alerts, nmap_output, gemini_analysis=""):
    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Helvetica", size=14)
    pdf.cell(0, 10, text="VAPT Report", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.ln(5)

    pdf.set_font("Helvetica", size=10)
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

    filename = os.path.join(REPORT_DIR, f"report_{int(time.time())}.pdf")
    pdf.output(filename)

    return filename


# -------------------------------
# SCAN ORCHESTRATION
# -------------------------------
def run_full_scan(url):
    domain = extract_domain(url)
    if not domain:
        return None, "Invalid URL"

    raw_alerts = zap_passive_scan(url)
    zap_alerts = normalize_zap_alerts(raw_alerts)
    nmap_output = run_nmap_scan(domain)

    gemini_result = analyze_with_gemini(zap_alerts, nmap_output, url)
    gemini_analysis = gemini_result.get("analysis", "")

    report_path = generate_pdf_report(zap_alerts, nmap_output, gemini_analysis)
    report_filename = basename(report_path)

    return {
        "url": url,
        "domain": domain,
        "zap_alerts": zap_alerts,
        "nmap_output": nmap_output,
        "report_filename": report_filename,
        "summary": count_alerts_by_risk(zap_alerts),
        "gemini": gemini_result,
    }, None


# -------------------------------
# API ROUTES
# -------------------------------
@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or request.form.get("url") or "").strip()

    if not url:
        return jsonify({"error": "Enter valid URL"}), 400

    result, error = run_full_scan(url)
    if error:
        return jsonify({"error": error}), 400

    return jsonify(result)


@app.route("/api/health", methods=["GET"])
def api_health():
    return jsonify(
        {
            "status": "ok",
            "gemini_configured": bool(GEMINI_API_KEY),
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
