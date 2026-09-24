# 🛡️ Typosquat & Brand Impersonation Threat Intelligence Platform
### Autonomous Real-Time Detection, Multi-Vector Threat Scoring & Legal Takedown Engine

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-v2.0-009688.svg)](https://fastapi.tiangolo.com)
[![Streamlit](https://img.shields.io/badge/Streamlit-SOC_Portal-FF4B4B.svg)](https://streamlit.io)
[![Playwright](https://img.shields.io/badge/Headless_Browser-Playwright_Chromium-45ba4b.svg)](https://playwright.dev)
[![Pytest](https://img.shields.io/badge/Pytest-20%2F20_Passed-brightgreen.svg)](https://pytest.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An enterprise-ready threat intelligence and automated incident response platform designed to detect, enrich, score, triage, alert, and generate registrar-ready legal takedown dossiers for typosquatting, IDN homoglyphs, and brand impersonation domains.

---

## 🏛️ System Architecture

```
[ Global Certificate Transparency (CT) Stream ] (rfc6962 WebSockets)
                      │
                      ▼
   [ Permutation & Combosquat Filter ] (dnstwist lookalike fuzzer + keywords)
                      │
        (Match Detected: Non-Blocking Enqueue)
                      │
                      ▼
        [ Worker Pool Queue (ThreadPoolExecutor) ]
          ├─ Worker 1
          ├─ Worker 2
          └─ Worker N
                      │
                      ▼
       [ Multi-Vector Forensic Enrichment Engine ]
        ├─ 1. Punycode / IDN Decoder   (RFC 3492: reveals confusable Cyrillic homoglyphs)
        ├─ 2. DNS & IP Resolver        (OS socket: confirms active IPv4 weaponization)
        ├─ 3. MX Mail Server Check     (RFC 5321: spear-phishing & spoofing readiness)
        ├─ 4. SSL/TLS Telemetry        (x509: short-lived automated DV cert profiling)
        ├─ 5. Headless Chromium Engine (Playwright: captures candidate screenshot)
        ├─ 6. Perceptual Hashing       (pHash: 64-bit DCT Hamming distance vs brand reference)
        ├─ 7. DOM Signal Parser        (BeautifulSoup: <input type='password'> & phishing lures)
        └─ 8. RDAP Registry Query      (HTTPS: authoritative registrar & abuse contacts)
                      │
                      ▼
       [ Composite Risk Scoring Engine ] (0 - 100 weighted threat model)
                      │
        ┌─────────────┴─────────────┐
        ▼                           ▼
[ HIGH Risk Threat (>= 70) ]   [ SQLite DB Storage ]
 ├─ Telegram Alert Bot          ├─ Streamlit SOC Portal (dashboard/app.py)
 └─ Automated PDF Takedown      └─ FastAPI REST Backend (src/api/main.py)
    Dossier (ICANN UDRP)
```

---

## ✨ Key Capabilities & Engineering Features

- **Transport-Layer Real-Time Ingestion**: Evaluates newly issued SSL/TLS certificates globally from Certificate Transparency logs via WebSockets before campaigns launch.
- **Asynchronous Non-Blocking Workers**: Ingestion filters incoming certificates in $<2$ ms and offloads heavy enrichment (Playwright screenshots, DNS, RDAP) to a background thread pool (`ThreadPoolExecutor`).
- **Homoglyph & Punycode Decoding**: Converts Internationalized Domain Names (IDNs) (`xn--...`) into Unicode to expose deceptive Cyrillic/Greek lookalikes (e.g. Cyrillic `а` spoofing Latin `a`).
- **Perceptual Image Hashing (pHash)**: Quantifies visual similarity against authentic brand reference screenshots using 64-bit DCT hashes and Hamming distance calculation.
- **Spear-Phishing MX Infrastructure Detection**: Probes mail exchanger records to detect if lookalikes are configured for executive spoofing or email deception.
- **SSL/TLS Telemetry Profiling**: Evaluates certificate issuer (Let's Encrypt, ZeroSSL) and validity duration.
- **DOM Credential Harvester Identification**: Parses rendered HTML DOM for password fields (`<input type="password">`) and social engineering keywords (*verify account*, *unusual activity*).
- **Network-Resilient RDAP**: Queries HTTPS-based RDAP (`rdap.org`) for registrar and abuse contacts, bypassing raw port 43 firewall blocks.
- **Multi-Brand Monitoring Catalog**: Simultaneously defends multiple brands (PayPal, Flipkart, Google, GitHub) with custom thresholds and keyword dictionaries.
- **Automated Legal Takedown PDF Dossier**: Automatically compiles a court-ready evidence dossier with side-by-side screenshots, forensic telemetry, and ICANN UDRP / RAA Section 3.18 notices.
- **Interactive SOC Security Operations Portal**: Streamlit-based analyst dashboard featuring incident triage lifecycles (`new`, `investigating`, `takedown_requested`, `resolved`), side-by-side screenshot comparisons, and an on-demand domain scanner.
- **Enterprise REST API**: FastAPI backend with full OpenAPI/Swagger documentation (`/docs`).

---

## 📊 Composite Risk Scoring Formula

$$Score = \min\left(100, \sum_{i=1}^{6} w_i \cdot s_i\right)$$

| Signal Vector | Weight ($w_i$) | Description |
| :--- | :---: | :--- |
| **DNS Resolution** | **20 pts** | Domain actively resolves to an IPv4/IPv6 host. |
| **Visual Similarity** | **30 pts** | Perceptual hash distance ($1 - \frac{d_{pHash}}{64}$) vs brand reference. |
| **Credential Harvester** | **20 pts** | Presence of `<form>` with `<input type="password">` in DOM. |
| **Phishing Lures** | **10 pts** | Scaled keyword match (*verify your account*, *unusual activity*, etc.). |
| **Email Infrastructure** | **10 pts** | Active Mail Exchanger (MX) records configured. |
| **SSL Telemetry** | **10 pts** | Automated / short-lived Domain Validation (DV) certificate profile. |

- 🔴 **HIGH RISK**: Score $\ge 70$ (Escalates to incident response, Telegram alerts & PDF takedown dossier)
- 🟠 **MEDIUM RISK**: Score $50 - 69$ (Active watchlist)
- 🟢 **LOW RISK**: Score $< 50$ (Parked / informational)

---

## 🚀 Quick Start Guide

### 1. Prerequisites
- Python 3.10+
- Linux / macOS / Windows WSL

### 2. Turnkey Launch Script
Use the master turnkey runner script to launch any project component:

```bash
# Make script executable
chmod +x run_project.sh

# Interactive launch menu:
./run_project.sh
```

Or invoke components directly:

| Command | Action |
| :--- | :--- |
| `./run_project.sh dashboard` | Launch the **Streamlit SOC Portal** (`http://localhost:8501`) |
| `./run_project.sh api` | Launch the **FastAPI REST Backend** (`http://localhost:8000/docs`) |
| `./run_project.sh simulate` | Run the **Live CT Stream Simulator** for presentation demos |
| `./run_project.sh demo` | Run High-Risk Threat Pipeline & Generate Legal PDF Dossier |
| `./run_project.sh seed` | Seed database with realistic multi-brand threat records |
| `./run_project.sh test` | Run the automated **Pytest** test suite (20/20 tests) |

---

## 📁 Repository Structure

```
typosquat-monitor/
├── config/
│   └── brand_config.yaml            # Monitored multi-brand catalog & thresholds
├── dashboard/
│   └── app.py                       # Streamlit SOC Threat Intelligence Portal
├── data/
│   ├── monitor.db                   # SQLite database with schema migrations
│   └── screenshots/                 # Captured candidate screenshots
├── reference_assets/                # Brand reference screenshots & metadata
├── reports/                         # Generated PDF takedown dossiers
├── src/
│   ├── alerts/
│   │   └── telegram_bot.py          # Telegram incident notification bot
│   ├── api/
│   │   └── main.py                  # FastAPI REST API backend & Swagger UI
│   ├── enrichment/
│   │   ├── content_signals.py       # HTML DOM form & keyword parser
│   │   ├── dns_check.py             # OS-level DNS IPv4 resolver
│   │   ├── mail_check.py            # MX mail infrastructure inspector
│   │   ├── pipeline.py              # Unified multi-vector enrichment pipeline
│   │   ├── punycode_decoder.py      # IDN / Punycode homoglyph converter
│   │   ├── screenshot.py            # Playwright headless browser engine
│   │   ├── ssl_check.py             # TLS certificate telemetry extractor
│   │   ├── visual_similarity.py     # Perceptual hashing (pHash) comparator
│   │   └── whois_lookup.py          # RDAP HTTPS registrar & abuse lookup
│   ├── ingest/
│   │   ├── ct_simulator.py          # Real-time CT stream simulator for live demos
│   │   ├── ct_stream_client.py      # Non-blocking WebSocket CT stream listener
│   │   └── permutation_filter.py    # dnstwist lookalike generator & filter
│   ├── reporting/
│   │   ├── report_generator.py      # Jinja2 + xhtml2pdf takedown compiler
│   │   └── templates/
│   │       └── takedown_report.html.j2 # Legal takedown dossier HTML template
│   ├── scoring/
│   │   └── risk_score.py            # Multi-vector composite threat scoring
│   └── storage/
│       └── db.py                    # SQLite models, migrations & triage CRUD
├── tests/
│   ├── test_api.py                  # FastAPI endpoint integration tests
│   ├── test_permutation.py          # dnstwist lookalike tests
│   ├── test_punycode.py             # Homoglyph decoding tests
│   ├── test_reporting.py            # PDF dossier generation tests
│   ├── test_scoring.py              # Risk scoring mathematical tests
│   └── test_storage.py              # Database lifecycle & filter tests
├── run_project.sh                   # Turnkey CLI launcher script
├── seed_data.py                     # Demo threat intelligence database seeder
├── demo_high_risk_trigger.py        # Pipeline simulation & PDF generator
├── Dockerfile                       # Production container specification
├── docker-compose.yml               # Multi-container service orchestration
├── FINAL_YEAR_PROJECT_REPORT.md     # Academic project report & dissertation
├── VIVA_QUESTIONS_AND_ANSWERS.md    # 25+ Viva defense questions and answers
├── PRESENTATION_GUIDE.md            # Step-by-step presentation & demo guide
└── requirements.txt                 # Project dependencies
```

---

## 🧪 Automated Testing & Verification

The platform includes a comprehensive Pytest test suite covering risk scoring mathematical bounds, punycode decoding, lookalike generation, database CRUD, PDF generation, and REST API endpoints:

```bash
pytest tests/ -v
```

```
============================== test session starts ==============================
tests/test_api.py::test_api_root PASSED                                  [  5%]
tests/test_api.py::test_api_metrics PASSED                               [ 10%]
tests/test_api.py::test_api_brands PASSED                                [ 15%]
tests/test_api.py::test_api_candidates_list PASSED                       [ 20%]
tests/test_api.py::test_api_status_update PASSED                         [ 25%]
tests/test_permutation.py::test_build_permutation_set PASSED             [ 30%]
tests/test_permutation.py::test_own_brand_not_flagged PASSED             [ 35%]
tests/test_permutation.py::test_typo_is_flagged PASSED                   [ 40%]
tests/test_permutation.py::test_combosquatting_match PASSED              [ 45%]
tests/test_permutation.py::test_multi_brand_matching PASSED              [ 50%]
tests/test_punycode.py::test_plain_domain PASSED                         [ 55%]
tests/test_punycode.py::test_punycode_decoding PASSED                    [ 60%]
tests/test_punycode.py::test_invalid_punycode PASSED                     [ 65%]
tests/test_reporting.py::test_pdf_generation PASSED                      [ 70%]
tests/test_scoring.py::test_weights_sum_to_100 PASSED                    [ 75%]
tests/test_scoring.py::test_max_score_is_100 PASSED                      [ 80%]
tests/test_scoring.py::test_zero_score_for_dormant PASSED                [ 85%]
tests/test_scoring.py::test_risk_level_thresholds PASSED                 [ 90%]
tests/test_scoring.py::test_partial_weights PASSED                       [ 95%]
tests/test_storage.py::test_db_lifecycle PASSED                          [100%]
============================== 20 passed in 2.35s ===============================
```

---

## 🎓 Academic Deliverables Included

For university evaluations and final year project defense, this repository includes:
1. **[Academic Project Report / Dissertation](FINAL_YEAR_PROJECT_REPORT.md)**: Full IEEE/academic format with Abstract, Problem Statement, Literature Review, Mathematical Model, Implementation, and Evaluation.
2. **[Viva Voce Questions & Answers](VIVA_QUESTIONS_AND_ANSWERS.md)**: 25+ in-depth viva questions covering networking, IDN homoglyphs, CT logs (RFC 6962), pHash, legal frameworks (ICANN UDRP), and architecture.
3. **[Presentation & Demo Walkthrough](PRESENTATION_GUIDE.md)**: Complete demonstration script and slide roadmap for presenting to examiners.

---

## ⚖️ Legal & Ethical Compliance

This platform is developed strictly for **defensive cybersecurity, brand protection, and academic research**. Takedown evidence reports conform to the **ICANN Uniform Domain-Name Dispute-Resolution Policy (UDRP)** and **ICANN Registrar Accreditation Agreement (RAA) Section 3.18**.

---

## 📄 License
Released under the [MIT License](LICENSE).
