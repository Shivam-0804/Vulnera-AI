def generate_report_file(url, alerts, nmap_output):
    with open("vulnerability_report.txt", "w") as f:
        f.write(f"Vulnerability Report for {url}\n")
        f.write("="*50 + "\n\n")

        f.write(" Nmap Scan Results:\n")
        f.write(nmap_output + "\n\n")

        f.write(" ZAP Vulnerability Alerts:\n")
        for alert in alerts:
            f.write(f"- Alert: {alert['alert']}\n")
            f.write(f"  Risk: {alert['risk']}\n")
            f.write(f"  Description: {alert['description']}\n")
            f.write(f"  URL: {alert['url']}\n")
            f.write(f"  Solution: {alert['solution']}\n\n")

    return "vulnerability_report.txt"
