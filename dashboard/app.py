"""
app.py
Typosquat & Brand Impersonation Threat Intelligence Platform
Enterprise SOC Analyst Portal & Incident Response Dashboard.
"""

import sys
import os
from datetime import datetime, timezone

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import streamlit as st
import pandas as pd
import altair as alt

from src.storage.db import (
    init_db,
    get_all_candidates,
    get_candidate_by_id,
    update_status,
    get_metrics_summary,
    insert_candidate,
    update_liveness,
    update_screenshot_path,
    update_visual_similarity,
    update_content_signals,
    update_mail_and_ssl,
    update_risk_score,
    update_takedown_report,
)
from src.ingest.permutation_filter import (
    get_all_monitored_brands,
    build_permutation_set,
)
from src.enrichment.pipeline import analyze_domain
from src.reporting.report_generator import generate_report
from src.scoring.risk_score import explain_scoring_formula

# Configure Streamlit Page
st.set_page_config(
    page_title="Typosquat & Brand Threat Intelligence SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize Database
init_db()

# Custom CSS for Sleek SOC Appearance
st.markdown("""
<style>
    .metric-card {
        background-color: #1e293b;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 14px 18px;
        color: white;
    }
    .badge-high {
        background-color: #ef4444;
        color: white;
        padding: 4px 10px;
        border-radius: 12px;
        font-weight: 600;
        font-size: 12px;
    }
    .badge-medium {
        background-color: #f59e0b;
        color: black;
        padding: 4px 10px;
        border-radius: 12px;
        font-weight: 600;
        font-size: 12px;
    }
    .badge-low {
        background-color: #10b981;
        color: white;
        padding: 4px 10px;
        border-radius: 12px;
        font-weight: 600;
        font-size: 12px;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        padding-top: 10px;
        padding-bottom: 10px;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)


# ------------------------------------------------------------------------------
# Sidebar Controls
# ------------------------------------------------------------------------------
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=64)
    st.title("Typosquat SOC")
    st.caption("Real-Time Brand Protection & Takedown Engine")
    st.divider()

    st.subheader("⚡ Quick Actions")
    if st.button("🔄 Refresh Data Feed", use_container_width=True):
        st.rerun()

    st.divider()
    st.subheader("📡 System Status")
    st.success("CT Log Stream: Active")
    st.info("Worker Pool: 5 Threads Ready")
    st.info("Storage: SQLite (Local DB)")
    
    st.divider()
    st.caption("Final Year Capstone Project\nDepartment of Computer Science & Cybersecurity")


# ------------------------------------------------------------------------------
# Header & KPI Metrics Row
# ------------------------------------------------------------------------------
metrics = get_metrics_summary()

st.title("🛡️ Typosquat & Brand Impersonation Threat Monitor")
st.markdown("Automated detection, multi-signal enrichment, risk scoring, and legal takedown generation platform.")

m_col1, m_col2, m_col3, m_col4, m_col5, m_col6 = st.columns(6)
m_col1.metric("Total Candidates", metrics["total"])
m_col2.metric("Critical Threats (HIGH)", metrics["high"], delta="Alerts Triggered", delta_color="inverse")
m_col3.metric("Medium Risk", metrics["medium"])
m_col4.metric("Active Takedowns", metrics["takedowns_active"])
m_col5.metric("Threats Resolved", metrics["resolved"])
m_col6.metric("Avg Threat Score", f"{metrics['avg_risk_score']}/100")

st.divider()

# ------------------------------------------------------------------------------
# Navigation Tabs
# ------------------------------------------------------------------------------
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🚨 Threat Intelligence Feed",
    "🔬 Forensic Evidence & Dossier",
    "🔍 On-Demand Domain Scanner",
    "🌐 Monitored Brands & Permutations",
    "📘 Project Architecture & Defense"
])


# ==============================================================================
# TAB 1: Threat Intelligence Feed & Incident Triage
# ==============================================================================
with tab1:
    st.subheader("Live Threat Candidates Feed")
    
    # Filter Controls
    f_col1, f_col2, f_col3, f_col4 = st.columns(4)
    
    with f_col1:
        search_query = st.text_input("🔍 Search Domain", placeholder="e.g. flipkart, paypa1...")
    with f_col2:
        brands_list = ["All Brands"] + [b["official_domain"] for b in get_all_monitored_brands()]
        selected_brand = st.selectbox("🎯 Matched Brand", brands_list)
    with f_col3:
        selected_risk = st.selectbox("⚠️ Risk Severity", ["All Severities", "HIGH", "MEDIUM", "LOW"])
    with f_col4:
        selected_status = st.selectbox("📌 Triage Status", ["All Statuses", "new", "investigating", "takedown_requested", "resolved", "false_positive"])

    # Fetch Filtered Data
    brand_filter = None if selected_brand == "All Brands" else selected_brand
    risk_filter = None if selected_risk == "All Severities" else selected_risk
    status_filter = None if selected_status == "All Statuses" else selected_status
    search_filter = search_query.strip() if search_query.strip() else None

    candidates = get_all_candidates(brand=brand_filter, risk_level=risk_filter, status=status_filter, search=search_filter)

    if not candidates:
        st.info("No candidates matched current search/filter criteria.")
    else:
        df = pd.DataFrame(candidates)
        
        # Display Table Columns
        display_cols = [
            "id", "domain", "decoded_domain", "matched_brand", "risk_score",
            "risk_level", "is_live", "has_login_form", "has_mx_record", "status", "detected_at"
        ]
        
        # Color helper
        def highlight_risk(val):
            if val == "HIGH":
                return "background-color: rgba(239, 68, 68, 0.25); color: #ef4444; font-weight: bold;"
            elif val == "MEDIUM":
                return "background-color: rgba(245, 158, 11, 0.25); color: #f59e0b; font-weight: bold;"
            elif val == "LOW":
                return "background-color: rgba(16, 185, 129, 0.25); color: #10b981; font-weight: bold;"
            return ""

        styled_df = df[display_cols].style.map(highlight_risk, subset=["risk_level"])
        st.dataframe(styled_df, use_container_width=True, hide_index=True)

        st.caption(f"Showing {len(candidates)} detected records.")

        # Interactive Status Updater
        st.subheader("⚡ Incident Triage Action Center")
        u_col1, u_col2, u_col3 = st.columns([2, 2, 4])
        
        candidate_ids = [c["id"] for c in candidates]
        selected_id = u_col1.selectbox("Select Candidate ID to Triage", candidate_ids, format_func=lambda x: f"ID #{x} — {[c['domain'] for c in candidates if c['id'] == x][0]}")
        new_status = u_col2.selectbox("Update Triage Status", ["new", "investigating", "takedown_requested", "resolved", "false_positive"])
        analyst_note = u_col3.text_input("Analyst Investigation Note", placeholder="e.g. Verified phishing form; abuse report dispatched to Namecheap.")

        if st.button("💾 Apply Incident Status Update", type="primary"):
            update_status(selected_id, new_status, notes=analyst_note if analyst_note else None)
            st.success(f"Candidate #{selected_id} updated to '{new_status}'!")
            st.rerun()


# ==============================================================================
# TAB 2: Forensic Evidence & Dossier Inspector
# ==============================================================================
with tab2:
    st.subheader("Threat Forensics & Side-by-Side Visual Inspection")

    all_cand = get_all_candidates()
    if not all_cand:
        st.info("No candidate records available to inspect.")
    else:
        inspect_id = st.selectbox(
            "Select Threat Candidate to Inspect",
            [c["id"] for c in all_cand],
            format_func=lambda x: f"ID #{x} — {[c['domain'] for c in all_cand if c['id'] == x][0]} (Score: {[c['risk_score'] for c in all_cand if c['id'] == x][0]}/100)"
        )

        item = get_candidate_by_id(inspect_id)
        if item:
            # Threat Banner
            b_col1, b_col2, b_col3 = st.columns([3, 2, 2])
            with b_col1:
                st.markdown(f"### `{item['domain']}`")
                if item.get("decoded_domain"):
                    st.markdown(f"**Decoded Homoglyph (IDN):** `{item['decoded_domain']}`")
                st.markdown(f"**Targeted Enterprise Brand:** `{item['matched_brand']}`")
                st.markdown(f"**Incident Triage Status:** `{item['status']}`")

            with b_col2:
                r_level = item.get("risk_level", "LOW")
                r_score = item.get("risk_score", 0.0)
                st.metric("Threat Risk Score", f"{r_score}/100", f"Level: {r_level}")

            with b_col3:
                # PDF Download button if exists or generate on fly
                report_path = item.get("takedown_report_path")
                if not report_path or not os.path.exists(report_path):
                    if st.button("📄 Generate Takedown PDF", key=f"gen_{item['id']}"):
                        from src.enrichment.whois_lookup import get_whois_info
                        whois = get_whois_info(item["domain"])
                        report_path = generate_report(item, whois)
                        if report_path:
                            update_takedown_report(item["id"], report_path)
                            st.success("Takedown PDF generated!")
                            st.rerun()

                if report_path and os.path.exists(report_path):
                    with open(report_path, "rb") as f:
                        pdf_bytes = f.read()
                    st.download_button(
                        label="⬇️ Download Takedown Dossier (PDF)",
                        data=pdf_bytes,
                        file_name=os.path.basename(report_path),
                        mime="application/pdf",
                        type="primary"
                    )

            st.divider()

            # Visual Evidence Side-by-Side
            st.markdown("#### 📸 Side-by-Side Visual Identity Comparison")
            v_col1, v_col2 = st.columns(2)

            with v_col1:
                st.info(f"Authentic Official Brand: **{item['matched_brand']}**")
                from src.enrichment.screenshot import get_brand_reference_path
                ref_img = get_brand_reference_path(item['matched_brand'])
                if ref_img and os.path.exists(ref_img):
                    st.image(ref_img, caption="Official Brand Reference Site", use_container_width=True)
                else:
                    st.warning("Official reference screenshot not cached.")

            with v_col2:
                st.error(f"Infringing Candidate Site: **{item['domain']}**")
                cand_img = item.get("screenshot_path")
                if cand_img and os.path.exists(cand_img):
                    st.image(cand_img, caption="Captured Headless Playwright Screenshot", use_container_width=True)
                else:
                    st.warning("Candidate screenshot not available (Domain inactive or screenshot timed out).")

            st.divider()

            # Multi-Vector Forensic Signal Indicators
            st.markdown("#### 📊 Multi-Vector Forensic Breakdown")
            f_col1, f_col2, f_col3 = st.columns(3)
            
            with f_col1:
                st.markdown("**Network & DNS Telemetry**")
                st.write(f"- **DNS Liveness:** {'🟢 Active & Resolving' if item.get('is_live') else '🔴 Offline / Inactive'}")
                st.write(f"- **Resolved IPv4:** `{item.get('ip_address') or 'Unresolved'}`")
                st.write(f"- **Active MX Records:** {'🚨 DETECTED' if item.get('has_mx_record') else 'None'}")

            with f_col2:
                st.markdown("**Content & Visual Indicators**")
                v_sim = item.get('visual_similarity')
                sim_pct = f"{round(v_sim * 100, 1)}%" if v_sim is not None else "N/A"
                st.write(f"- **pHash Visual Similarity:** `{sim_pct}`")
                st.write(f"- **Login / Password Input:** {'🚨 CONFIRMED' if item.get('has_login_form') else 'No form found'}")
                st.write(f"- **Phishing Keywords:** `{item.get('suspicious_phrases') or 'None detected'}`")

            with f_col3:
                st.markdown("**TLS & Registrar Dossier**")
                st.write(f"- **SSL Issuer:** `{item.get('ssl_issuer') or 'None'}`")
                st.write(f"- **Analyst Investigation Notes:** {item.get('analyst_notes') or 'No notes logged yet.'}")


# ==============================================================================
# TAB 3: On-Demand Real-Time Domain Scanner
# ==============================================================================
with tab3:
    st.subheader("Interactive On-Demand Threat Scanner")
    st.markdown("Perform an immediate, live forensic evaluation on any suspicious URL or domain name.")

    scan_col1, scan_col2, scan_col3 = st.columns([3, 2, 2])
    with scan_col1:
        target_input = st.text_input("Domain or URL to Inspect", placeholder="e.g. paypa1-verification.net")
    with scan_col2:
        brands = [b["official_domain"] for b in get_all_monitored_brands()]
        target_brand = st.selectbox("Target Brand Comparison", brands)
    with scan_col3:
        st.write("")
        st.write("")
        trigger_scan = st.button("🚀 Run Live Forensic Scan", type="primary", use_container_width=True)

    if trigger_scan and target_input.strip():
        clean_target = target_input.strip().replace("https://", "").replace("http://", "").split("/")[0]
        
        with st.spinner(f"Running multi-vector threat inspection on '{clean_target}'..."):
            profile = analyze_domain(clean_target, matched_brand=target_brand, capture_screen=True, fetch_whois=True)

            # Insert into database
            cid = insert_candidate(profile["domain"], profile["matched_brand"], decoded_domain=profile["decoded_domain"])
            update_liveness(cid, profile["is_live"], ip_address=profile["ip_address"])
            if profile["screenshot_path"]:
                update_screenshot_path(cid, profile["screenshot_path"])
                update_visual_similarity(cid, profile["visual_similarity"])
            update_content_signals(cid, profile["has_login_form"], profile["suspicious_phrases"])
            update_mail_and_ssl(cid, profile["has_mx_record"], profile["ssl_issuer"])
            update_risk_score(cid, profile["risk_score"], profile["risk_level"])

            # Generate report if high risk
            report_path = None
            if profile["risk_level"] == "HIGH":
                candidate_record = {
                    "id": cid,
                    "domain": profile["domain"],
                    "decoded_domain": profile["decoded_domain"],
                    "matched_brand": profile["matched_brand"],
                    "detected_at": "On-demand Live Scan",
                    "is_live": profile["is_live"],
                    "ip_address": profile["ip_address"],
                    "has_mx_record": profile["has_mx_record"],
                    "ssl_issuer": profile["ssl_issuer"],
                    "visual_similarity": profile["visual_similarity"],
                    "has_login_form": profile["has_login_form"],
                    "suspicious_phrases": ", ".join(profile["suspicious_phrases"]),
                    "risk_score": profile["risk_score"],
                    "risk_level": profile["risk_level"],
                    "screenshot_path": profile["screenshot_path"],
                }
                report_path = generate_report(candidate_record, profile.get("whois_info", {}))
                if report_path:
                    update_takedown_report(cid, report_path)

        st.success(f"Scan complete for **{clean_target}**! Candidate recorded as ID #{cid}.")

        # Display Live Result Card
        r1, r2, r3, r4 = st.columns(4)
        r1.metric("Risk Score", f"{profile['risk_score']}/100")
        r2.metric("Threat Severity", profile["risk_level"])
        r3.metric("Liveness", "LIVE" if profile["is_live"] else "OFFLINE")
        r4.metric("Credential Harvester", "YES" if profile["has_login_form"] else "NO")

        # Score Breakdown Chart
        breakdown_df = pd.DataFrame([
            {"Signal": k.replace("_", " ").title(), "Points": v}
            for k, v in profile["score_breakdown"].items()
        ])
        chart = alt.Chart(breakdown_df).mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4).encode(
            x=alt.X("Signal:N", sort="-y", title="Signal Vector"),
            y=alt.Y("Points:Q", title="Points Contributed"),
            color=alt.Color("Signal:N", legend=None)
        ).properties(height=240)
        st.altair_chart(chart, use_container_width=True)

        if report_path and os.path.exists(report_path):
            with open(report_path, "rb") as f:
                st.download_button("⬇️ Download Generated Takedown PDF", f.read(), file_name=os.path.basename(report_path), mime="application/pdf")


# ==============================================================================
# TAB 4: Monitored Brands & Permutations Catalog
# ==============================================================================
with tab4:
    st.subheader("Enterprise Monitored Brands & Lookalike Generation")
    brands_catalog = get_all_monitored_brands()

    b_cols = st.columns(len(brands_catalog))
    for i, b in enumerate(brands_catalog):
        with b_cols[i]:
            st.markdown(f"### {b['brand_name'].title()}")
            st.write(f"**Domain:** `{b['official_domain']}`")
            st.write(f"**Category:** {b.get('category', 'Enterprise')}")
            st.write(f"**Similarity Threshold:** `{b.get('similarity_threshold', 0.8)}`")
            st.caption(f"Keywords: {', '.join(b.get('keywords', []))}")

    st.divider()

    st.subheader("🔤 Algorithmic Permutation Generator (dnstwist)")
    perm_domain = st.text_input("Test Permutation Generator on Domain", value="paypal.com")
    if st.button("Generate Permutations"):
        with st.spinner("Calculating typosquat permutations..."):
            perms = build_permutation_set(perm_domain)
            st.success(f"Generated **{len(perms)}** algorithmic permutations for `{perm_domain}`!")
            
            sample_perms = sorted(list(perms))[:40]
            col1, col2, col3, col4 = st.columns(4)
            split = len(sample_perms) // 4
            col1.write(sample_perms[:split])
            col2.write(sample_perms[split:split*2])
            col3.write(sample_perms[split*2:split*3])
            col4.write(sample_perms[split*3:])


# ==============================================================================
# TAB 5: System Architecture & Viva Defense Reference
# ==============================================================================
with tab5:
    st.subheader("System Architecture & Mathematical Threat Model")
    st.markdown("""
    This section summarizes the core engineering principles, mathematical formulation,
    and compliance mechanisms implemented in this platform for project defense and presentation.
    """)

    st.markdown("### 🏛️ End-to-End Pipeline Architecture")
    st.markdown("""
    ```
    [ Global CT Log WebSocket Stream ] (rfc6962 transparency logs)
                    │
                    ▼
     [ Permutation & Combosquat Filter ] (dnstwist homoglyphs + keyword heuristics)
                    │
                    ▼
          [ Worker Pool Queue ] (concurrent ThreadPoolExecutor)
                    │
                    ▼
       [ Multi-Vector Enrichment Engine ]
        ├─ 1. Punycode / IDN Decoder (RFC 3492: reveals confusable Cyrillic homoglyphs)
        ├─ 2. DNS & IP Resolver (OS-level socket: active weaponization check)
        ├─ 3. MX Mail Server Check (RFC 5321: spear-phishing & email spoofing vector)
        ├─ 4. SSL/TLS Telemetry (x509: short-lived DV cert detection)
        ├─ 5. Headless DOM Inspection (Playwright Chromium: <input type='password'>)
        ├─ 6. Perceptual Hashing (pHash: 64-bit DCT perceptual image distance)
        └─ 7. RDAP Registry Query (HTTPS REST: authoritative registrar & abuse contacts)
                    │
                    ▼
       [ Composite Risk Scoring Engine ] (0 - 100 weighted threat formulation)
                    │
        ┌───────────┴───────────┐
        ▼                       ▼
    [ HIGH RISK (>= 70) ]   [ SQLite DB Storage ]
        ├─ Telegram Alert Bot   └─ Streamlit SOC Portal & FastAPI REST Interface
        └─ Automated PDF Takedown Dossier (xhtml2pdf legal exhibit)
    ```
    """)

    st.markdown(explain_scoring_formula())

    st.markdown("### ⚖️ Legal & Takedown Enforcement Framework")
    st.markdown("""
    - **ICANN UDRP (Uniform Domain-Name Dispute-Resolution Policy)**: Governs bad-faith trademark registrations and abusive domain disputes.
    - **ICANN Registrar Accreditation Agreement (RAA) Section 3.18**: Mandates that accredited registrars maintain an abuse contact and investigate actionable reports of phishing and malware.
    - **Automated Evidence Dossier**: Generates concrete exhibits including timestamped side-by-side screenshots, perceptual hash distance calculations, DOM credential harvesters, and MX records to expedite registrar domain suspension (`ClientHold`).
    """)
