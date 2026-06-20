<div align="center">

# 🛡️ CyberShield — Police Edition

### AI-Powered Cybercrime Intelligence & Forensic Operations Platform

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.30+-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)](https://streamlit.io)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org)
[![SQLite](https://img.shields.io/badge/SQLite-Database-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://sqlite.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

> A forensic-grade, AI-driven cybercrime management system built for Indian law enforcement. Classifies complaints, detects scam messages, analyzes phishing URLs with a hybrid ML/rule-based engine, maps suspect networks, and auto-generates legal notices under IPC/BNS & IT Act.

</div>

---

## 📑 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Architecture](#-architecture)
- [Project Structure](#-project-structure)
- [Tech Stack](#-tech-stack)
- [Installation & Setup](#-installation--setup)
- [Running the Application](#-running-the-application)
- [Module Deep Dive](#-module-deep-dive)
  - [Citizen Complaint Portal](#1-citizen-complaint-portal)
  - [Officer Command Center](#2-officer-command-center)
  - [Complaint NLP Analyzer](#3-complaint-nlp-analyzer)
  - [Scam Message Detector](#4-scam-message-detector)
  - [Phishing URL Forensic Lab](#5-phishing-url-forensic-lab)
  - [Suspect Intelligence Network](#6-suspect-intelligence-network)
  - [AI Legal & Forensic Assistant](#7-ai-legal--forensic-assistant)
- [Machine Learning Pipelines](#-machine-learning-pipelines)
  - [Complaint Categorizer](#1-complaint-categorizer)
  - [SMS Scam Detector](#2-sms-scam-detector)
  - [Phishing URL Classifier](#3-phishing-url-classifier)
- [Phishing Forensics Engine](#-phishing-forensics-engine)
  - [16-Feature Extraction](#16-feature-url-extraction)
  - [5-Component Hybrid Scoring](#5-component-hybrid-scoring-pipeline)
  - [Rule Engine](#forensic-rule-engine)
- [Database Schema](#-database-schema)
- [Verification & Testing](#-verification--testing)
- [Legal Framework Reference](#-legal-framework-reference)
- [Screenshots](#-screenshots)
- [Future Roadmap](#-future-roadmap)
- [Contributors](#-contributors)

---

## 🔎 Overview

**CyberShield Police Edition** is a full-stack cybercrime intelligence platform designed as a prototype for Indian law enforcement agencies. It provides:

- A **Citizen Portal** for public complaint intake with AI-powered auto-classification.
- An **Officer Command Center** with dashboards, case management, forensic tools, and suspect mapping.
- **Three independent ML models** for complaint categorization, SMS scam detection, and phishing URL classification.
- A **hybrid forensic engine** that combines ML predictions with rule-based analysis, brand spoofing detection, protocol anomaly checks, and domain reputation whitelisting to eliminate false positives.
- **Auto-generated legal notices** (Section 91 CrPC) and IPC/BNS/IT Act section recommendations.

The system is built entirely in Python using **Streamlit** for the web UI, **scikit-learn** for ML, **SQLite** for persistence, and **Plotly/NetworkX** for interactive visualizations.

---

## ✨ Key Features

| Feature | Description |
|---|---|
| **AI Complaint Classification** | NLP pipeline (TF-IDF + Random Forest) auto-classifies complaints into 10 cybercrime categories |
| **Risk & Severity Scoring** | Multi-factor scoring engine with base severity, monetary modifiers, urgency language detection, and repeat offender correlation |
| **Scam SMS/WhatsApp Detector** | Multinomial Naive Bayes classifier with keyword extraction and threat language analysis |
| **Phishing URL Forensic Lab** | 16-feature extraction → 5-component hybrid scoring (Protocol + Rules + Brand Spoof + Reputation + ML) |
| **Repeat Offender Detection** | Entity-linking across cases (phone numbers, URLs, UPI IDs, social handles) with automatic alerts |
| **Suspect Network Graph** | Interactive NetworkX/Plotly graph mapping relationships between cases and suspect entities |
| **Legal Notice Generator** | Auto-generates Section 91 CrPC notices with pre-filled case details, applicable IPC/BNS/IT Act sections |
| **Admin Model Retraining** | Self-contained pipeline for retraining the phishing model from within the UI with live progress |
| **Executive Dashboard** | Real-time metrics, crime category distribution, risk heatmaps, and daily incident trend charts |
| **Premium Dark UI** | Glassmorphism design system with custom CSS, hover animations, and forensic-grade terminal styling |

---

## 🏗 Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    STREAMLIT WEB UI (app.py)                  │
│  ┌─────────────────┐  ┌──────────────────────────────────┐   │
│  │  Citizen Portal  │  │     Officer Command Center        │   │
│  │  - Complaint Form│  │  - Dashboard    - Case Mgmt      │   │
│  │  - Evidence Input│  │  - Analyzer     - Scam Detector   │   │
│  │  - Auto-classify │  │  - Phishing Lab - Suspect Graph   │   │
│  └────────┬────────┘  │  - AI Legal Assistant              │   │
│           │           └──────────────┬───────────────────┘   │
├───────────┴──────────────────────────┴───────────────────────┤
│                     INTELLIGENCE LAYER                        │
│  ┌─────────────────┐ ┌────────────────┐ ┌────────────────┐   │
│  │ Complaint Model  │ │ SMS Scam Model │ │ Phishing Model │   │
│  │ (TF-IDF + RF)    │ │ (TF-IDF + NB)  │ │ (16-feat + RF) │   │
│  └─────────────────┘ └────────────────┘ └────────┬───────┘   │
│                                                   │           │
│  ┌────────────────────────────────────────────────┴───────┐   │
│  │          Hybrid Forensics Engine (phishing_forensics.py)│   │
│  │  Protocol Check │ Rule Engine │ Brand Spoof │ Whitelist │   │
│  └────────────────────────────────────────────────────────┘   │
├──────────────────────────────────────────────────────────────┤
│                      DATA LAYER                               │
│  ┌─────────────────┐  ┌────────────┐  ┌──────────────────┐   │
│  │  database.py     │  │ models/    │  │   datasets/      │   │
│  │  (SQLite ORM)    │  │ (.pkl/.jl) │  │  (.parquet/.csv) │   │
│  └─────────────────┘  └────────────┘  └──────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

---

## 📂 Project Structure

```
prototype 2/
├── app.py                     # Main Streamlit application (1094 lines)
│                              # - Citizen Portal, Officer Command Center
│                              # - All 7 operational modules
│
├── phishing_forensics.py      # Hybrid Phishing Forensics Engine (465 lines)
│                              # - 16-feature URL extraction
│                              # - 5-component hybrid scoring pipeline
│                              # - Rule engine, brand spoofing, whitelist
│
├── database.py                # SQLite ORM layer (239 lines)
│                              # - Cases & evidence tables
│                              # - Suspect intelligence queries
│                              # - Auto-seeds 6 mock cases on first run
│
├── train_models.py            # Offline model training script (223 lines)
│                              # - Generates synthetic complaint dataset (600 samples)
│                              # - Generates synthetic SMS dataset (750 samples)
│                              # - Trains complaint categorizer (RF)
│                              # - Trains SMS scam detector (NB)
│                              # - Triggers phishing URL model pipeline
│
├── train_phishing_model.py    # Repeatable phishing model pipeline (237 lines)
│                              # - Auto-detects CSV/Parquet columns
│                              # - 16-feature extraction from URLs
│                              # - Trains RF & LR, selects best by F1
│                              # - Saves model + metrics JSON
│
├── verify.py                  # System verification suite (161 lines)
│                              # - Tests DB, ML models, phishing forensics
│                              # - Runs 7 URL test cases with expected results
│
├── styles.css                 # Premium dark theme CSS (248 lines)
│                              # - Glassmorphism cards, badges, animations
│                              # - Custom scrollbars, evidence terminal
│
├── requirements.txt           # Python dependencies
├── cybershield.db             # SQLite database (auto-created)
├── .gitignore                 # Git exclusions
│
├── models/                    # Trained ML model binaries
│   ├── complaint_vectorizer.pkl    # TF-IDF vectorizer for complaints
│   ├── complaint_model.pkl         # Random Forest complaint classifier
│   ├── scam_vectorizer.pkl         # TF-IDF vectorizer for SMS
│   ├── scam_model.pkl              # Multinomial NB scam detector
│   ├── phishing_model.joblib       # Best phishing URL classifier (RF)
│   ├── phishing_model.pkl          # Legacy fallback phishing model
│   └── phishing_metrics.json       # Training metrics & dataset stats
│
└── datasets/                  # Training datasets
    ├── Training.parquet       # Primary phishing URL training data (~789 KB)
    ├── Testing.parquet        # Phishing URL test data (~431 KB)
    ├── balanced_urls.csv      # Large balanced URL dataset (~46 MB)
    └── url-phishing-model-raw-url.ipynb  # Exploratory notebook
```

---

## 🛠 Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Frontend** | Streamlit 1.30+ | Web UI framework with reactive widgets |
| **Styling** | Custom CSS (Outfit font) | Glassmorphism dark theme, animations |
| **ML** | scikit-learn | TF-IDF, Random Forest, Logistic Regression, Naive Bayes |
| **Serialization** | pickle / joblib | Model persistence |
| **Visualization** | Plotly + NetworkX | Interactive charts, heatmaps, network graphs |
| **Database** | SQLite3 | Lightweight relational storage |
| **Data** | pandas / numpy | Data manipulation and feature engineering |
| **Language** | Python 3.10+ | Core runtime |

---

## 🚀 Installation & Setup

### Prerequisites

- **Python 3.10+** installed
- **pip** package manager
- **Git** (optional, for cloning)

### Step-by-Step

```bash
# 1. Clone the repository
git clone https://github.com/tarungupta786/Cyber-Shield-.git
cd "prototype 2"

# 2. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install additional required packages
pip install joblib pyarrow

# 5. Train all ML models (first-time setup — takes 2-5 minutes)
python train_models.py

# 6. Verify system integrity
python verify.py
```

> **Note:** The `train_models.py` script generates synthetic datasets for the complaint and SMS classifiers, then trains the phishing URL model using `datasets/Training.parquet`. All model binaries are saved to `models/`.

---

## ▶️ Running the Application

```bash
# Start the Streamlit server
streamlit run app.py
```

The application opens at **http://localhost:8501** with two portal views:

| Portal | Access | Description |
|---|---|---|
| **Officer Control Room** | Default view | Full intelligence console with 7 modules |
| **Citizen Intake Portal** | Sidebar toggle | Public complaint submission form |

---

## 🔬 Module Deep Dive

### 1. Citizen Complaint Portal

The public-facing form where citizens report cybercrimes.

**Workflow:**
1. Citizen fills in name, contact, and incident description
2. Optional evidence checkboxes: SMS content, email, URLs, transaction details, suspect phone/social handle
3. On submission:
   - NLP model classifies the complaint into one of **10 crime categories**
   - Risk engine calculates severity (base + monetary modifier + urgency modifier + repeat offender bonus)
   - Unique Case ID generated (format: `CS-2026-XXXX`)
   - Case + evidence entities stored in SQLite
   - Confirmation card with Case ID, category, and priority displayed

**Crime Categories:**
`UPI Fraud` · `Banking Fraud` · `Loan Scam` · `Lottery Scam` · `Investment Scam` · `Job Scam` · `Delivery Scam` · `Sextortion` · `Social Media Fraud` · `Phishing Attack`

---

### 2. Officer Command Center

**Executive Dashboard** — Real-time operational overview:
- Total complaints, active investigations, escalated threats, tracked financial theft
- Crime category bar chart (Viridis color scale)
- Risk heatmap matrix (Category × Priority)
- Daily incident filing trend line
- High-risk repeat suspect entity table

---

### 3. Complaint NLP Analyzer

Ad-hoc tool for officers to paste any complaint description and get instant AI classification:
- Predicted crime category
- Severity score (0–10) with breakdown: base severity + urgency modifier + monetary modifier
- Priority assignment (High ≥ 7.5, Medium ≥ 5.0, Low < 5.0)
- Extracted financial amounts (regex: `Rs.`, `INR`, `Rupees`)

---

### 4. Scam Message Detector

SMS/WhatsApp forensic scanner:
- ML probability score (Naive Bayes)
- Sub-category classification (Lottery, Banking Phishing, Job Task, Loan App, Delivery/Utility)
- Text analysis flags: urgency markers, threat markers, fraud keywords, extracted links
- Generates a ready-to-attach **Digital Evidence Report** with timestamp

---

### 5. Phishing URL Forensic Lab

The flagship forensic module — a complete URL threat intelligence system:

**Admin Retraining Panel:**
- Displays active model metrics (accuracy, precision, recall, F1, dataset composition)
- One-click model retraining with live Streamlit progress bar
- Supports custom dataset paths (CSV or Parquet)

**URL Analysis Output:**
- Threat level badge: `Safe` · `Low Risk` · `Suspicious` · `High Risk` · `Critical`
- Final hybrid risk percentage
- Triggered forensic rules list
- Investigation notes (protocol, hostname, keywords, entropy, Unicode checks)
- 5-component contribution progress bars
- Recommended enforcement action
- Full digital forensic evidence summary report

---

### 6. Suspect Intelligence Network

Entity-linking and relationship mapping:
- Table of all evidence entities with linked case counts
- **Interactive network graph** (Plotly):
  - 🔵 Cyan nodes = Case files
  - 🟡 Yellow nodes = Single-case suspect entities
  - 🔴 Red nodes = **Repeat offenders** linked to multiple cases
- Spring-layout algorithm with hover tooltips

---

### 7. AI Legal & Forensic Assistant

Auto-generates a complete investigation briefing for any case:

1. **AI Case Summary** — Synthesized narrative from complaint description
2. **IPC/BNS & IT Act Sections** — Category-specific legal references (e.g., Sec 66C/66D IT Act, Sec 318(4) BNS)
3. **Recommended Technical Investigations** — Bank communications, domain takedowns, CDR requests, platform preservation orders
4. **Section 91 CrPC Legal Notice Template** — Pre-filled with case ID, suspect details, applicable sections, and bank/payment gateway info

---

## 🤖 Machine Learning Pipelines

### 1. Complaint Categorizer

| Property | Value |
|---|---|
| **Algorithm** | Random Forest Classifier (100 estimators) |
| **Vectorizer** | TF-IDF (max 2500 features, bigrams) |
| **Training Data** | 600 synthetic complaints (60 per category) |
| **Categories** | 10 cybercrime types |
| **Output** | `models/complaint_model.pkl` + `models/complaint_vectorizer.pkl` |

### 2. SMS Scam Detector

| Property | Value |
|---|---|
| **Algorithm** | Multinomial Naive Bayes |
| **Vectorizer** | TF-IDF (max 1500 features) |
| **Training Data** | 750 samples (375 scam + 375 ham) |
| **Classes** | `scam` / `ham` |
| **Output** | `models/scam_model.pkl` + `models/scam_vectorizer.pkl` |

### 3. Phishing URL Classifier

| Property | Value |
|---|---|
| **Algorithms** | Random Forest (100 est.) + Logistic Regression (max 1000 iter) |
| **Selection** | Best model by F1 score |
| **Features** | 16 structural URL features (see below) |
| **Training Data** | `datasets/Training.parquet` (real-world URLs) |
| **Split** | 75% train / 25% test (stratified) |
| **Output** | `models/phishing_model.joblib` + `models/phishing_metrics.json` |
| **Retrainable** | Yes — via UI admin panel or CLI: `python train_phishing_model.py --dataset <path>` |

---

## 🔗 Phishing Forensics Engine

The core of the phishing detection system lives in `phishing_forensics.py`.

### 16-Feature URL Extraction

| # | Feature | Description |
|---|---|---|
| 0 | `length_url` | Total character length of the URL |
| 1 | `length_domain` | Character length of the hostname |
| 2 | `nb_dots` | Count of `.` characters |
| 3 | `nb_hyphens` | Count of `-` characters |
| 4 | `nb_special_chars` | Count of `@`, `?`, `=`, `&`, `_`, `%` |
| 5 | `is_https` | 1 if URL starts with `https://`, else 0 |
| 6 | `has_ip` | 1 if hostname is a raw IP address |
| 7 | `query_params_count` | Number of query parameters |
| 8 | `path_length` | Character length of the URL path |
| 9 | `num_subdomains` | Count of subdomain levels |
| 10 | `entropy` | Shannon entropy of hostname characters |
| 11 | `keyword_count` | Matches against 17 suspicious keywords |
| 12 | `domain_reputation_flag` | 0.0 = whitelisted, 1.0 = untrusted |
| 13 | `trusted_domain_flag` | 1.0 = whitelisted, 0.0 = untrusted |
| 14 | `brand_similarity_score` | Levenshtein-based brand spoofing score |
| 15 | `anomaly_score` | Protocol malformation flag (htttps, hxxps, etc.) |

### 5-Component Hybrid Scoring Pipeline

Each component contributes **20%** to the final risk score:

```
Final Risk = 0.20 × Protocol + 0.20 × Rules + 0.20 × Brand Spoof + 0.20 × Reputation + 0.20 × ML
```

| Component | Score Range | Description |
|---|---|---|
| **Protocol Validation** | 0.0 (HTTPS) / 0.5 (HTTP) / 1.0 (malformed) | Detects `htttps`, `hxxps`, and other anomalies |
| **Forensic Rule Engine** | 0.0 – 1.0 | 8 configurable rules (IP, TLD, subdomains, keywords, shorteners, Unicode) |
| **Brand Spoofing** | 0.0 – 1.0 | Levenshtein distance against 12 monitored brands |
| **Domain Reputation** | 0.0 (trusted) / 1.0 (untrusted) | Checked against 22 whitelisted domains |
| **ML Classifier** | 0.0 – 1.0 | Trained model probability output |

**Threat Levels:**

| Risk % | Level | Badge Color |
|---|---|---|
| < 10% | Safe | 🟢 Green |
| 10–20% | Low Risk | 🔵 Blue |
| 20–55% | Suspicious | 🟡 Amber |
| 55–87% | High Risk | 🔴 Red |
| ≥ 87% | Critical | 🔴 Glowing Red |

### Forensic Rule Engine

8 rules evaluated per URL:

1. **Invalid Protocol Anomaly** (+0.25) — Malformed `htttps`, `hxxps`, etc.
2. **Raw IP Address** (+0.30) — Hostname resolves to IP instead of domain
3. **Brand Spoofing** (+0.35) — Levenshtein similarity ≥ 70% to monitored brand
4. **Suspicious TLD** (+0.15) — `.xyz`, `.ru`, `.cc`, `.info`, `.tk`, etc.
5. **Excessive Subdomains** (+0.15) — More than 2 subdomain levels
6. **Credential Keywords** (+0.15) — `login`, `secure`, `verify`, `bank`, etc.
7. **URL Shortener** (+0.20) — `bit.ly`, `tinyurl.com`, `t.co`, etc.
8. **Unicode Obfuscation** (+0.25) — IDN Homograph attack (`xn--` prefix)

---

## 🗄 Database Schema

**SQLite** (`cybershield.db`) with two tables:

### `cases` Table

| Column | Type | Description |
|---|---|---|
| `case_id` | TEXT PK | Format: `CS-2026-XXXX` |
| `citizen_name` | TEXT | Reporter's full name |
| `complaint_desc` | TEXT | Detailed incident description |
| `category` | TEXT | AI-classified crime category |
| `severity_score` | REAL | Calculated severity (0–10) |
| `risk_score` | REAL | Final risk with repeat offender bonus (0–10) |
| `priority` | TEXT | `High` / `Medium` / `Low` |
| `status` | TEXT | `Open` / `Under Investigation` / `Escalated` / `Closed` |
| `officer_name` | TEXT | Assigned investigating officer |
| `created_at` | TEXT | Timestamp of filing |
| `investigation_notes` | TEXT | Officer's investigation log |
| `sms_text` | TEXT | Attached scam SMS content |
| `email_text` | TEXT | Attached phishing email content |
| `fraud_url` | TEXT | Reported fraudulent URL |
| `transaction_details` | TEXT | Financial loss details |
| `phone_number` | TEXT | Suspect's contact number |
| `social_media_username` | TEXT | Suspect's social handle |

### `evidence` Table

| Column | Type | Description |
|---|---|---|
| `id` | INTEGER PK | Auto-increment |
| `case_id` | TEXT FK | References `cases.case_id` |
| `evidence_type` | TEXT | `Phone Number` / `URL` / `Bank Account` / `UPI ID` / `Social Media Handle` |
| `evidence_value` | TEXT | The actual entity value |
| `details` | TEXT | Context description |

The database **auto-seeds 6 realistic mock cases** with 11 evidence entities on first run, including a deliberately shared phone number (`+91 98765 43210`) across 3 cases to demonstrate repeat offender detection.

---

## ✅ Verification & Testing

Run the system verification suite:

```bash
python verify.py
```

**Tests performed:**

| Test | What it checks |
|---|---|
| `test_database()` | SQLite file exists, cases load, suspects load, sample case retrieval |
| `test_models()` | All 4 pkl files exist, complaint categorizer predicts, SMS detector predicts |
| `test_phishing_forensics()` | Loads phishing model, runs 7 URL test cases through the full hybrid pipeline |

**Phishing test cases included:**

| URL | Expected Threat Level |
|---|---|
| `https://www.youtube.com/results?search_query=...` | Safe |
| `https://google.com` | Safe |
| `https://github.com` | Safe |
| `htttps.MicRosoft.com` | Suspicious |
| `http://g00gle-login.xyz` | High Risk |
| `http://paypal-security-check.ru` | Critical |
| `http://micr0soft.com` | High Risk |

---

## ⚖️ Legal Framework Reference

The system maps each crime category to applicable **Indian Penal Code (BNS 2023)** and **IT Act 2000** sections:

| Category | Primary Sections |
|---|---|
| UPI Fraud | Sec 66D IT Act, Sec 318(4) BNS |
| Banking Fraud | Sec 66C, 66D IT Act, Sec 318(4) BNS |
| Loan Scam | Sec 66D IT Act, Sec 318(4) BNS, Sec 308 BNS |
| Lottery Scam | Sec 66D IT Act, Sec 318(4) BNS |
| Investment Scam | Sec 66D IT Act, Sec 318(4) BNS, Sec 316 BNS |
| Job Scam | Sec 66D IT Act, Sec 318(4) BNS |
| Delivery Scam | Sec 66D IT Act, Sec 318(4) BNS |
| Sextortion | Sec 66E, 67A IT Act, Sec 308, 351 BNS |
| Social Media Fraud | Sec 66C, 66D IT Act, Sec 319 BNS |
| Phishing Attack | Sec 66C, 66D IT Act, Sec 318(4) BNS |

---

## 📸 Screenshots

> Launch the application with `streamlit run app.py` to explore the full UI. Key views include:

- **Executive Dashboard** — Metrics cards, category distribution chart, risk heatmap, trend line
- **Case Management Board** — Priority-coded case cards with repeat offender alerts
- **Phishing Forensic Lab** — Threat level badge, 5-component progress bars, evidence terminal
- **Suspect Intelligence Graph** — Interactive network visualization with color-coded nodes
- **AI Legal Assistant** — Auto-generated case brief with Section 91 CrPC notice template

---

## 🗺 Future Roadmap

- [ ] **Real VirusTotal/URLScan API Integration** — Live domain reputation lookups
- [ ] **WHOIS Lookup Module** — Automated registrar and hosting provider queries
- [ ] **Multi-language NLP** — Hindi, Tamil, Telugu complaint classification
- [ ] **Deep Learning Models** — LSTM/BERT for complaint and URL classification
- [ ] **Role-Based Access Control** — Separate logins for citizens, officers, and admins
- [ ] **PostgreSQL Migration** — Production-grade database for deployment
- [ ] **PDF Report Export** — Downloadable case briefs and forensic reports
- [ ] **Real-time Alert System** — Push notifications for high-priority cases
- [ ] **Mobile Responsive UI** — Optimized layout for field officer tablets

---

## 👥 Contributors

| Name | Role |
|---|---|
| **Tarun Gupta** | Lead Developer & Architect |

---

## 📄 License

This project is developed as an academic prototype for cybercrime investigation assistance. It is intended for educational and demonstration purposes only.

---

<div align="center">

**CyberShield v2.5 Police Edition** · Built with 🐍 Python & ❤️ for Law Enforcement

</div>
