# Vulnera-AI

AI-Powered Vulnerability Assessment and Penetration Testing (VAPT) Platform

## Overview

Vulnera-AI is a web-based security assessment platform that combines traditional security scanning tools with AI-powered analysis to help identify and understand vulnerabilities in web applications.

The platform performs:

- Web application vulnerability scanning using OWASP ZAP
- Network reconnaissance using Nmap
- AI-powered security analysis using Google Gemini
- Automated PDF report generation
- Risk categorization and remediation recommendations

The application provides an easy-to-use React frontend and a Flask backend for conducting security assessments and generating professional vulnerability reports.

---

## Features

### Vulnerability Assessment

- OWASP ZAP Passive Scanning
- Detection of common web application vulnerabilities
- Risk-based vulnerability classification
- Alert normalization and categorization

### Network Scanning

- Fast Nmap scanning
- Open port discovery
- Service exposure analysis
- Network attack surface assessment

### AI Security Analysis

- Gemini-powered vulnerability interpretation
- Executive security summary
- Risk prioritization
- Actionable remediation recommendations

### Reporting

- Automatic PDF report generation
- Vulnerability summaries
- Risk breakdown
- Security recommendations

### Dashboard

- React-based modern UI
- Scan status visualization
- Vulnerability overview
- Downloadable reports

---

## Architecture

```text
                +----------------+
                | React Frontend |
                +--------+-------+
                         |
                         v
                +--------+-------+
                | Flask Backend  |
                +--------+-------+
                         |
          +--------------+--------------+
          |                             |
          v                             v
 +----------------+         +-------------------+
 | OWASP ZAP API  |         | Nmap Scanner      |
 +----------------+         +-------------------+
          |
          v
 +----------------+
 | Gemini AI      |
 | Security       |
 | Analysis       |
 +----------------+
          |
          v
 +----------------+
 | PDF Reports    |
 +----------------+
```

---

## Technology Stack

### Frontend

- React
- Vite
- React Markdown

### Backend

- Flask
- Flask-CORS
- Python

### Security Tools

- OWASP ZAP
- Nmap

### AI

- Google Gemini

### Reporting

- FPDF2

---

## Project Structure

```text
Vulnera-AI/
│
├── app.py
├── requirements.txt
├── reports/
│
├── frontend/
│   ├── src/
│   ├── public/
│   ├── package.json
│   └── vite.config.js
│
└── static/
    └── dist/
```

---

## Installation

### Prerequisites

Install the following:

- Python 3.10+
- Node.js 18+
- npm
- OWASP ZAP
- Nmap

---

## Clone Repository

```bash
git clone https://github.com/Shivam-0804/Vulnera-AI.git

cd Vulnera-AI
```

---

## Backend Setup

### Create Virtual Environment

Windows

```bash
python -m venv venv

venv\Scripts\activate
```

Linux/macOS

```bash
python3 -m venv venv

source venv/bin/activate
```

---

### Install Python Dependencies

```bash
pip install -r requirements.txt
```

---

## Environment Configuration

Create a `.env` file in the project root.

```env
GEMINI_API_KEY=your_gemini_api_key

ZAP_API_KEY=your_zap_api_key

ZAP_PROXY=http://localhost:8080
```

---

## OWASP ZAP Setup

### Start ZAP

Example:

```bash
zap.bat
```

or

```bash
zap.sh
```

### Enable API Access

In ZAP:

```text
Tools → Options → API
```

Configure:

- Enable API
- Set API key
- Allow local access

---

## Nmap Installation

### Windows

Download from:

https://nmap.org/download.html

Add Nmap to system PATH.

Verify:

```bash
nmap --version
```

### Linux

```bash
sudo apt install nmap
```

### macOS

```bash
brew install nmap
```

---

## Frontend Setup

```bash
cd frontend

npm install
```

### Development Mode

```bash
npm run dev
```

---

### Production Build

```bash
npm run build
```

The frontend build will be generated inside:

```text
frontend/dist
```

and served by Flask.

---

## Running the Application

From project root:

```bash
python app.py
```

Server:

```text
http://localhost:5000
```

---

## API Endpoints

### Health Check

```http
GET /api/health
```

Response:

```json
{
  "status": "ok",
  "gemini_configured": true
}
```

---

### Start Scan

```http
POST /api/scan
```

Request:

```json
{
  "url": "https://example.com"
}
```

Response:

```json
{
  "url": "https://example.com",
  "domain": "example.com",
  "summary": {
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Informational": 5
  },
  "zap_alerts": [],
  "nmap_output": "...",
  "report_filename": "report_123456.pdf"
}
```

---

### Download Report

```http
GET /download/<filename>
```

Example:

```http
GET /download/report_123456.pdf
```

---

## Scan Workflow

1. User enters target URL
2. Flask backend receives request
3. OWASP ZAP performs passive scan
4. Nmap scans network exposure
5. Gemini analyzes findings
6. PDF report generated
7. Results returned to frontend

---

## Generated Report Includes

- Executive Summary
- Vulnerability Overview
- Risk Breakdown
- Nmap Findings
- AI Security Analysis
- Recommended Fixes

---

## Security Notes

This project is intended for:

- Security research
- Educational purposes
- Authorized penetration testing
- Internal security assessments

Only scan systems you own or have explicit permission to test.

---
