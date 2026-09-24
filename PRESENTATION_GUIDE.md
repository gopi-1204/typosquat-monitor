# 🎯 Final Year Project Presentation & Demonstration Walkthrough

This guide gives you an exact, step-by-step blueprint to deliver a high-scoring, flawless final year project demonstration to your panel of examiners.

---

## 🕒 Demonstration Roadmap (10 - 15 Minutes)

### Stage 1: The Pitch & Problem Statement (2 minutes)
- **Opening line:**  
  *"Respected examiners, our project is an Autonomous Real-Time Threat Intelligence & Legal Takedown Platform for Typosquatting, IDN Homoglyphs, and Brand Impersonation."*
- **The Core Problem:**  
  Point out that attackers register deceptive domains (e.g. `paypa1.com` or `pаypal.com` with Cyrillic characters) and deploy credential harvesters. Traditional blacklists take 4 to 24 hours to react, during which thousands of users fall victim.
- **The Solution:**  
  We tap into **Certificate Transparency (CT) logs in real time** to detect lookalikes the second their SSL certificate is issued, score them across 6 forensic vectors, and compile instant legal takedown dossiers.

---

## 💻 Step-by-Step Live Demo Execution

### Step 1: Open the SOC Security Operations Portal
In terminal, run:
```bash
./run_project.sh dashboard
```
Open browser at: `http://localhost:8501`

**What to highlight to examiners:**
1. **Executive KPI Cards:** Point to Total Candidates, Critical Threats (HIGH), Active Takedowns, Resolved Threats, and Average Threat Score.
2. **Threat Feed Tab:**
   - Filter by Brand (e.g. `flipkart.com`, `paypal.com`, `google.com`).
   - Filter by Severity (`HIGH`, `MEDIUM`, `LOW`).
   - Filter by Status (`new`, `investigating`, `takedown_requested`, `resolved`).
   - Show the **Incident Triage Action Center**: select candidate #1, change status from `new` to `takedown_requested`, add a note like *"Registrar abuse ticket submitted"*, and click Save. Explain that this represents the real SOC analyst lifecycle!

---

### Step 2: Show Forensic Evidence & Side-by-Side Visual Inspection
1. Switch to **Tab 2: Forensic Evidence & Dossier**.
2. Select candidate: `flipkart-secure-login.com` or `xn--pypal-4ve.com`.
3. **Show Side-by-Side Screenshots:**
   - On the left: The authentic brand website.
   - On the right: The fraudulent lookalike captured by headless Playwright Chromium.
4. **Point to Perceptual Hash (pHash) Similarity:**  
   Explain that we use 64-bit DCT perceptual hashing and Hamming distance:
   $$\text{Similarity} = 1 - \frac{\text{Hamming Distance}}{64}$$
5. **Show Multi-Vector Forensic Indicators:**
   - IPv4 address resolution (DNS).
   - Credential harvesting form detection (`<input type="password">`).
   - MX mail server check (explaining spear-phishing vector).
   - TLS Certificate telemetry (Let's Encrypt / DV).
6. **Click "Download Takedown Dossier (PDF)":**
   - Open the generated PDF in front of the examiners.
   - Show the professional case reference (`TSM-INC-XXXX`), side-by-side visual exhibits, registrar abuse email, and formal ICANN UDRP / RAA 3.18 takedown notice!

---

### Step 3: Run the On-Demand Live Scanner
1. Switch to **Tab 3: On-Demand Domain Scanner**.
2. Type any suspicious candidate domain, e.g.:
   `flipkart-secure-login.com` or `paypa1-checkout-security.com`.
3. Select `flipkart.com` as target brand.
4. Click **"Run Live Forensic Scan"**.
5. Watch the system execute live DNS, MX, DOM, and Playwright inspection.
6. Show the resulting dynamic **Altair score breakdown chart** displaying the point contribution from each signal vector!

---

### Step 4: Show Brand Protection & Permutation Engine
1. Switch to **Tab 4: Monitored Brands & Permutations**.
2. Show the multi-brand catalog (PayPal, Flipkart, Google, GitHub).
3. In the Permutation Generator, type `paypal.com` and click **"Generate Permutations"**.
4. Show how `dnstwist` mathematically calculates dozens of homoglyphs, omissions, bitsquats, and transpositions.

---

### Step 5: Demonstrate Real-Time Ingestion (The "Wow" Factor!)
Open a second terminal window and run the live simulator:
```bash
./run_project.sh simulate
```
- The terminal will stream simulated global certificate issuance events.
- When an infringing domain arrives (e.g. `auth-google-accounts.net` or `xn--pypal-4ve.com`), show the terminal log output:
  `[STREAM MATCH] Flagged: ... -> Submitted to non-blocking worker pool`
- Switch back to the Streamlit Dashboard, click **"Refresh Data Feed"**, and show the new detection recorded in real time!

---

### Step 6: Show FastAPI REST Backend & Automated Test Suite
1. In terminal, run:
   ```bash
   ./run_project.sh api
   ```
   Open `http://localhost:8000/docs` in the browser to showcase the enterprise Swagger UI endpoints (`/api/metrics`, `/api/candidates`, `/api/scan`, `/api/report/{id}`).
2. In terminal, run the test suite:
   ```bash
   ./run_project.sh test
   ```
   Show all **20 pytest unit and integration tests passing with 100% green checkmarks**.

---

## 🏆 Examiner Closing Remarks
Conclude by stating:
*"Our platform successfully bridges the gap between proactive global transport-layer threat detection, computer vision similarity analysis, and automated legal takedown execution, offering an end-to-end cyber defense solution."*
