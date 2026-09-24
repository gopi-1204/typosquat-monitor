# 🎓 Final Year Project Defense & Viva Voce Q&A Guide
## Typosquat & Brand Impersonation Threat Intelligence Platform

This document prepares you for technical questions typically posed by university examiners, project review committees, and cybersecurity specialists during your project defense.

---

### Q1: What specific security problem does your project solve?
**Answer:**
My project solves the **Time-to-Weaponization Gap** in brand impersonation and phishing. Attackers register lookalike domains (typosquats, IDN homoglyphs, and combosquats) and acquire SSL certificates to launch phishing portals, steal credentials, and conduct spear-phishing. Traditional defenses rely on static blacklists (like Google Safe Browsing), which take 4 to 24 hours to verify and list malicious domains. By that time, the phishing campaign is already complete.  
Our platform monitors **Certificate Transparency (CT) logs in real time via WebSockets**, detecting infringing domains the exact second their SSL certificate is issued—often hours before the attacker even sends their first phishing email.

---

### Q2: How does the system ingest domain registrations in real time?
**Answer:**
We listen to public Certificate Transparency (CT) log streams governed by **RFC 6962**. Under modern browser security standards, every public TLS certificate issued by any Certificate Authority (Let's Encrypt, DigiCert, Cloudflare) must be logged to append-only Merkle cryptographic trees. Platforms like `certstream` aggregate these into a high-speed WebSocket feed. We ingest this stream in Python and immediately filter domain names against our monitored brands.

---

### Q3: What is an IDN Homograph / Homoglyph attack, and how do you handle it?
**Answer:**
An IDN (Internationalized Domain Name) homograph attack exploits visually identical or confusable glyphs from different character scripts. For example, Cyrillic Small Letter `а` (`U+0430`) looks identical to Latin Small Letter `a` (`U+0061`). When an attacker registers `pаypal.com` with the Cyrillic `а`, the Domain Name System encodes it using Punycode as `xn--pypal-4ve.com`.  
Our system uses the `idna` Python library to automatically decode any `xn--` prefix into its actual Unicode representation (`decode_domain`), exposing the lookalike trick and displaying the confusable character clearly in the analyst dashboard and takedown evidence report.

---

### Q4: What is Combosquatting vs. Typosquatting?
**Answer:**
- **Typosquatting:** Capitalizes on spelling or typographical errors (e.g. `flipkarrt.com`, `fli8pkart.com`, `paypa1.com`).
- **Combosquatting:** Combines a legitimate brand name with operational or security keywords (e.g. `flipkart-secure-login.com`, `paypal-verify-account.net`, `github-auth-token.io`).  
Our platform handles both: it uses `dnstwist` to generate mathematical lookalike permutations (omission, bitsquatting, transposition, homoglyphs) and regex/keyword heuristics to flag combosquatted domains containing authentication keywords.

---

### Q5: How does your Perceptual Hashing (pHash) visual similarity engine work?
**Answer:**
Unlike cryptographic hashes (SHA-256) where changing a single pixel causes a completely different avalanche hash, **Perceptual Hashing (pHash)** calculates the discrete cosine transform (DCT) of the image's low-frequency components. Visually identical or similar images generate very close 64-bit binary hashes.  
We compare the candidate screenshot's hash against the authentic brand's reference screenshot by computing the **Hamming Distance** (the number of differing bits between the two 64-bit hashes):
$$\text{Similarity} = 1 - \frac{\text{Hamming Distance}}{64}$$
A similarity score of 0.85 or higher indicates strong visual cloning of the target brand.

---

### Q6: Why did you decouple ingestion from enrichment using a worker pool?
**Answer:**
In an earlier prototype, incoming CT WebSocket events were processed synchronously. Performing DNS resolution, Playwright headless browser startup, and screenshot capture takes 4 to 15 seconds per live domain. During this time, the WebSocket event loop was blocked, resulting in dropped CT stream messages.  
To resolve this, we implemented a non-blocking architecture using `concurrent.futures.ThreadPoolExecutor`. Ingestion fast-filters domains in $<2$ ms; when a lookalike is flagged, it is submitted to the background worker pool while the WebSocket listener immediately resumes processing global certificates.

---

### Q7: Explain your Composite Risk Scoring Engine and its mathematical formula.
**Answer:**
We formulate the threat risk as a weighted linear combination bounded between 0 and 100:
$$\text{Risk Score} = \min\left(100, \sum w_i \cdot s_i\right)$$
The weights are distributed across 6 forensic vectors:
1. **DNS Liveness ($20\text{ pts}$):** Domain actively resolves to an IPv4 address.
2. **Visual Similarity ($30\text{ pts}$):** pHash similarity score scaled from 0.0 to 1.0 against brand reference.
3. **Credential Harvesting Form ($20\text{ pts}$):** DOM contains `<form>` with `<input type="password">`.
4. **Phishing Phrases ($10\text{ pts}$):** Presence of high-confidence social engineering lures (*verify account*, *unusual activity*).
5. **MX Mail Records ($10\text{ pts}$):** Active mail server infrastructure configured for spear-phishing or CEO fraud.
6. **SSL Telemetry ($10\text{ pts}$):** Automated / short-lived Domain Validation (DV) certificate profile.

Scores $\ge 70$ are classified as **HIGH RISK**, triggering automated incident alerts and takedown dossier generation.

---

### Q8: What happens when a HIGH-risk threat is detected?
**Answer:**
Three automated actions occur:
1. **Incident Record Saved:** Full forensic telemetry is stored in the database with status `new`.
2. **Real-Time Notification:** A structured alert is pushed to the security operations team via Telegram Bot API with the domain name, target brand, and risk score.
3. **Legal Takedown Dossier Generated:** A PDF report is generated containing side-by-side screenshots, pHash metrics, IP/DNS data, and registrar abuse emails formatted to substantiate immediate takedown under ICANN UDRP.

---

### Q9: Why use RDAP instead of traditional WHOIS?
**Answer:**
Traditional WHOIS operates over TCP port 43 using unstructured plaintext. Many academic networks and corporate firewalls block raw port 43 traffic. Furthermore, raw WHOIS responses lack standardization across different registrars.  
**RDAP (Registration Data Access Protocol)** is the modern IETF standard replacement operating over HTTPS (port 443) and returning structured JSON data. It queries `rdap.org`, easily traversing firewalls and providing clean registrar and abuse contact fields.

---

### Q10: What legal framework governs domain takedowns?
**Answer:**
Domain takedowns are governed primarily by:
1. **ICANN Registrar Accreditation Agreement (RAA) Section 3.18:** Requires all accredited registrars to maintain an operational abuse contact and investigate actionable reports of phishing, malware, and cybercrime.
2. **ICANN Uniform Domain-Name Dispute-Resolution Policy (UDRP):** Governs trademark infringement and bad-faith domain registrations.  
Our automated PDF report includes explicit references to these policies to facilitate expedited administrative suspension (`ClientHold`).

---

### Q11: How do you prevent false positives?
**Answer:**
We prevent false positives through multiple layers:
1. **Whitelisting:** The official brand domain and approved parent domains are explicitly exempted.
2. **Multi-Vector Scoring:** A benign site that happens to share a similar domain name will not score high because it will lack the authentic visual clone (0/30 pts), login password field (0/20 pts), and phishing lures (0/10 pts).
3. **Analyst Triage Lifecycle:** The SOC dashboard provides an interactive workflow where analysts can mark false positives, add investigation notes, and preserve audit logs.

---

### Q12: Why did you choose Playwright instead of Selenium?
**Answer:**
Playwright Chromium was chosen because:
- It runs faster than Selenium and requires no external `chromedriver` binary management.
- It operates natively via the Chrome DevTools Protocol (CDP).
- It provides built-in `wait_until="domcontentloaded"` and auto-waiting mechanisms, avoiding flaky sleep calls.
- It cleanly executes in headless mode inside Docker Linux containers.

---

### Q13: What is the purpose of the FastAPI REST API?
**Answer:**
In an enterprise environment, threat intelligence platforms cannot exist as isolated silos; they must integrate with existing Security Information and Event Management (SIEM) systems (like Splunk or Microsoft Sentinel) or ticketing systems (like Jira Service Desk). Our FastAPI backend exposes clean endpoints (`/api/metrics`, `/api/candidates`, `/api/scan`, `/api/report/{id}`) with interactive Swagger documentation at `/docs`.

---

### Q14: How does the On-Demand Domain Scanner in the dashboard work?
**Answer:**
An analyst can paste any suspicious domain or URL (e.g. from an employee phishing email submission), select the target brand, and click "Run Live Forensic Scan". The system executes the entire multi-signal enrichment pipeline in real time (DNS, MX, SSL, DOM, Playwright screenshot, pHash comparison, and risk scoring) and renders the visual identity comparison, score breakdown chart, and takedown PDF directly on screen.

---

### Q15: If the live CT stream or external WebSocket is unreachable during an offline exam, how can you demonstrate the system?
**Answer:**
We developed a dedicated **CT Stream Simulator (`src/ingest/ct_simulator.py`)** specifically for turnkey demonstration and offline defense. It simulates high-velocity certificate issuance events, interleaving benign traffic with weaponized homoglyphs and typosquats, triggering live detection, scoring, alerting, and dashboard updates in front of the examiners.
