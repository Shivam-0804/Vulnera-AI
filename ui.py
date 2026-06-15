import threading
import streamlit as st
import requests
import time

from app import app, SCAN_TYPES, DEFAULT_SCAN_TYPE

# -------------------------------
# Run Flask in background thread
# -------------------------------
def run_flask():
    app.run(port=5000, debug=False, use_reloader=False)

if "flask_started" not in st.session_state:
    thread = threading.Thread(target=run_flask, daemon=True)
    thread.start()
    st.session_state["flask_started"] = True
    time.sleep(2)

# -------------------------------
# Streamlit UI
# -------------------------------
st.set_page_config(page_title="AI VAPT Tool", layout="wide")

st.title("🔍 AI-Powered VAPT Scanner")
st.markdown("Vulnerability scanning using ZAP + Nmap + Gemini AI")

url = st.text_input("Enter Target URL", placeholder="https://example.com")

scan_options = {cfg["label"]: key for key, cfg in SCAN_TYPES.items()}
selected_label = st.selectbox(
    "Scan Type",
    options=list(scan_options.keys()),
    index=0,
)
scan_type = scan_options[selected_label]
st.caption(SCAN_TYPES[scan_type]["description"])

timeout_map = {"passive": 300, "normal": 600, "deep": 1800}

if st.button("Start Scan"):
    if not url:
        st.warning("Please enter a URL")
    else:
        with st.spinner(f"Running {selected_label}... please wait ⏳"):
            try:
                response = requests.post(
                    "http://127.0.0.1:5000/api/scan",
                    json={"url": url, "scan_type": scan_type},
                    timeout=timeout_map.get(scan_type, 600),
                )

                if response.status_code == 200:
                    data = response.json()
                    st.success(f"Scan Completed ✅ — {data.get('scan_label', scan_type)}")

                    summary = data.get("summary", {})
                    st.subheader("ZAP Alert Summary")
                    cols = st.columns(4)
                    for i, risk in enumerate(["High", "Medium", "Low", "Informational"]):
                        cols[i].metric(risk, summary.get(risk, 0))

                    gemini = data.get("gemini", {})
                    if gemini.get("available") and gemini.get("analysis"):
                        st.subheader("✨ AI Security Analysis")
                        st.markdown(gemini["analysis"])

                    st.subheader("🧭 Nmap Output")
                    st.code(data.get("nmap_output", ""), language="text")

                    report = data.get("report_filename")
                    if report:
                        st.markdown(
                            f"[⬇️ Download PDF Report](http://127.0.0.1:5000/download/{report})"
                        )
                else:
                    err = response.json().get("error", response.status_code)
                    st.error(f"Error: {err}")

            except Exception as e:
                st.error(f"Connection Error: {str(e)}")
