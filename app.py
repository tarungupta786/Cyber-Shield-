import os
import re
import pickle
import math
import sqlite3
import joblib
from collections import Counter
from urllib.parse import urlparse
from datetime import datetime
import numpy as np
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import networkx as nx
import database as db
import auth

from phishing_forensics import (
    extract_url_features,
    run_hybrid_forensics,
    get_registered_domain
)
from train_phishing_model import train_and_evaluate

# Set Streamlit Page Configuration
st.set_page_config(
    page_title="CyberShield Police Edition",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load Custom CSS Styling
def load_css():
    if os.path.exists("styles.css"):
        with open("styles.css", "r") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
    else:
        st.warning("Custom stylesheet (styles.css) not found. Falling back to default layout.")



# ==========================================
# MACHINE LEARNING MODELS LOADING
# ==========================================
@st.cache_resource
def load_ml_models():
    models = {}
    try:
        with open("models/complaint_vectorizer.pkl", "rb") as f:
            models["comp_vec"] = pickle.load(f)
        with open("models/complaint_model.pkl", "rb") as f:
            models["comp_model"] = pickle.load(f)
        with open("models/scam_vectorizer.pkl", "rb") as f:
            models["scam_vec"] = pickle.load(f)
        with open("models/scam_model.pkl", "rb") as f:
            models["scam_model"] = pickle.load(f)
        
        # Load phishing model via Joblib first, with pkl fallback
        if os.path.exists("models/phishing_model.joblib"):
            models["phish_model"] = joblib.load("models/phishing_model.joblib")
        elif os.path.exists("models/phishing_model.pkl"):
            with open("models/phishing_model.pkl", "rb") as f:
                models["phish_model"] = pickle.load(f)
        else:
            st.warning("Phishing model binary not found. Please train model using the training panel.")
    except FileNotFoundError:
        st.error("Pre-trained model files not found! Please run train_models.py first to build them.")
    except Exception as e:
        st.error(f"Error loading models: {e}")
    return models

models = load_ml_models()

def parse_transaction_amount(text):
    # Regex to extract numeric amount after Rs. or INR or Rs or Rupees
    match = re.search(r'(?:rs\.?|inr|rupees|rs)\s*(\d+(?:,\d+)*(?:\.\d+)?)', text, re.IGNORECASE)
    if match:
        val = match.group(1).replace(",", "")
        try:
            return float(val)
        except ValueError:
            return 0.0
    return 0.0

def calculate_severity_base(category):
    severities = {
        "Sextortion": 9.0,
        "Banking Fraud": 8.5,
        "Phishing Attack": 8.0,
        "UPI Fraud": 7.5,
        "Investment Scam": 7.5,
        "Loan Scam": 7.0,
        "Job Scam": 6.0,
        "Social Media Fraud": 5.5,
        "Lottery Scam": 5.0,
        "Delivery Scam": 5.0
    }
    return severities.get(category, 5.0)

def generate_ipc_references(category):
    refs = {
        "UPI Fraud": [
            ("Section 66D, IT Act", "Cheating by personation using computer resource (up to 3 years imprisonment & fine)."),
            ("Section 318(4), Bharatiya Nyaya Sanhita (BNS) [Formerly Sec 420 IPC]", "Cheating and dishonestly inducing delivery of property (up to 7 years imprisonment & fine).")
        ],
        "Banking Fraud": [
            ("Section 66C, IT Act", "Identity theft (using card PINs, passwords - up to 3 years & fine)."),
            ("Section 66D, IT Act", "Cheating by personation using computer resource."),
            ("Section 318(4), BNS [Sec 420 IPC]", "Cheating and dishonestly inducing delivery of property.")
        ],
        "Loan Scam": [
            ("Section 66D, IT Act", "Cheating by personation using computer resource."),
            ("Section 318(4), BNS [Sec 420 IPC]", "Cheating and fraud."),
            ("Section 308, BNS [Sec 384 IPC]", "Extortion / harassment by loan recovery agents (up to 3 years & fine).")
        ],
        "Lottery Scam": [
            ("Section 66D, IT Act", "Cheating by personation using computer resource."),
            ("Section 318(4), BNS [Sec 420 IPC]", "Cheating and dishonestly inducing delivery of property.")
        ],
        "Investment Scam": [
            ("Section 66D, IT Act", "Cheating by personation using computer resource."),
            ("Section 318(4), BNS [Sec 420 IPC]", "Cheating and fraud."),
            ("Section 316, BNS [Sec 406 IPC]", "Criminal breach of trust (up to 3 years & fine).")
        ],
        "Job Scam": [
            ("Section 66D, IT Act", "Cheating by personation using computer resource."),
            ("Section 318(4), BNS [Sec 420 IPC]", "Cheating and fraud.")
        ],
        "Delivery Scam": [
            ("Section 66D, IT Act", "Cheating by personation using computer resource."),
            ("Section 318(4), BNS [Sec 420 IPC]", "Cheating and fraud.")
        ],
        "Sextortion": [
            ("Section 66E, IT Act", "Violation of privacy (capturing/publishing private images - up to 3 years & fine)."),
            ("Section 67A, IT Act", "Publishing material containing sexually explicit conduct (up to 5 years & fine)."),
            ("Section 308, BNS [Sec 384 IPC]", "Extortion (forcing money transfers under threat of defamation)."),
            ("Section 351, BNS [Sec 506 IPC]", "Criminal intimidation.")
        ],
        "Social Media Fraud": [
            ("Section 66C, IT Act", "Identity theft (creating fake profiles using someone else's pictures)."),
            ("Section 66D, IT Act", "Cheating by personation using computer resource."),
            ("Section 319, BNS [Sec 419 IPC]", "Punishment for cheating by personation.")
        ],
        "Phishing Attack": [
            ("Section 66C, IT Act", "Identity theft (stealing usernames/passwords via cloned sites)."),
            ("Section 66D, IT Act", "Cheating by personation using computer resource."),
            ("Section 318(4), BNS [Sec 420 IPC]", "Cheating and fraud.")
        ]
    }
    return refs.get(category, [("Section 66, IT Act", "Computer related offences.")])

# ==========================================
# CITIZEN INTAKE PORTAL
# ==========================================
def render_citizen_portal():
    st.markdown("<h1>🛡️ CyberShield Citizen Complaint Portal</h1>", unsafe_allow_html=True)
    st.markdown("<p style='color:#a1a1aa;'>Report cybercrimes directly to Law Enforcement. Complaints are processed using AI models for fast allocation.</p>", unsafe_allow_html=True)

    # Citizen tabs: File Complaint + My Cases (if logged in)
    if auth.is_authenticated() and auth.get_current_role() == "citizen":
        citizen_tab = st.radio("Select", ["📝 File New Complaint", "📋 My Complaints"], horizontal=True)
        if citizen_tab == "📋 My Complaints":
            _render_my_cases()
            return

    st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
    st.subheader("1. Reporter Information")
    # Auto-fill name for logged-in citizens
    default_name = auth.get_current_user()["full_name"] if auth.is_authenticated() else ""
    col1, col2 = st.columns(2)
    with col1:
        citizen_name = st.text_input("Full Name", value=default_name, placeholder="e.g. john doe")
    with col2:
        contact_no = st.text_input("Mobile Number", placeholder="e.g. +91 99999 99999")
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
    st.subheader("2. Cybercrime Details")
    complaint_desc = st.text_area(
        "Describe the incident in detail *", 
        placeholder="Provide details about what happened, how you were contacted, what details you shared, and any money lost.",
        height=150
    )
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
    st.subheader("3. Evidence Collection (Optional, check all that apply)")
    
    has_sms = st.checkbox("Scam SMS / Message Content Received")
    sms_text = ""
    if has_sms:
        sms_text = st.text_area("Paste SMS / WhatsApp Message", height=80, placeholder="e.g. SBI block KYC card...")

    has_email = st.checkbox("Phishing Email Content")
    email_text = ""
    if has_email:
        email_text = st.text_area("Paste Email Subject & Body", height=80)

    has_url = st.checkbox("Fraudulent URL / Link")
    fraud_url = ""
    if has_url:
        fraud_url = st.text_input("Enter Scam Website URL", placeholder="e.g. http://secure-kyc-sbi.net")

    has_transaction = st.checkbox("Transaction / Financial Details")
    transaction_details = ""
    phone_number = ""
    social_media_username = ""
    if has_transaction:
        transaction_details = st.text_input("Enter Amount Lost, Bank, Txn ID", placeholder="e.g. Lost Rs. 20000 from SBI A/c, Txn ID 92839182")
    
    has_phone = st.checkbox("Suspect Phone Number")
    if has_phone:
        phone_number = st.text_input("Enter Suspect's Contact Number", placeholder="e.g. +91 98765 43210")

    has_social = st.checkbox("Suspect Social Media Username")
    if has_social:
        social_media_username = st.text_input("Enter Suspect's Social Profile / Handle", placeholder="e.g. @easy_cash_agent")
    
    st.markdown("</div>", unsafe_allow_html=True)

    # Submit Button
    if st.button("Submit Secure Complaint", type="primary", use_container_width=True):
        if not citizen_name or not complaint_desc:
            st.error("Please fill in your name and describe the incident.")
        else:
            # 1. NLP Classification of Complaint Category
            if "comp_model" in models and "comp_vec" in models:
                text_vectorized = models["comp_vec"].transform([complaint_desc])
                predicted_category = models["comp_model"].predict(text_vectorized)[0]
            else:
                predicted_category = "UPI Fraud"  # Fallback
            
            # 2. Risk & Severity Engine calculations
            severity_base = calculate_severity_base(predicted_category)
            
            # Adjust severity based on monetary loss
            amount_lost = parse_transaction_amount(transaction_details) + parse_transaction_amount(complaint_desc)
            monetary_mod = min(1.5, amount_lost / 50000.0)
            
            # Check for urgent language keywords
            urgency_mod = 0.5 if any(w in (complaint_desc.lower() + sms_text.lower()) for w in ["urgent", "immediately", "cut", "block", "arrester", "threat"]) else 0.0
            
            severity_score = min(10.0, severity_base + monetary_mod + urgency_mod)
            
            # Link check for repeat offenders
            linked_cases_mod = 0.0
            if phone_number:
                matches = db.get_linked_cases_by_entity("Phone Number", phone_number)
                linked_cases_mod += 1.5 * len(matches)
            if fraud_url:
                matches = db.get_linked_cases_by_entity("URL", fraud_url)
                linked_cases_mod += 1.5 * len(matches)
            
            risk_score = min(10.0, severity_score + linked_cases_mod)
            priority = "High" if risk_score >= 7.5 else "Medium" if risk_score >= 5.0 else "Low"
            
            # 3. Generate unique Case ID
            # Fetch last case ID to increment
            all_c = db.get_all_cases()
            if not all_c.empty:
                max_id = all_c["case_id"].iloc[0]  # Order is DESC by created_at, let's parse safely
                all_numeric_ids = []
                for cid in all_c["case_id"]:
                    try:
                        all_numeric_ids.append(int(cid.split("-")[-1]))
                    except ValueError:
                        pass
                new_num = max(all_numeric_ids) + 1 if all_numeric_ids else 7
            else:
                new_num = 7
            case_id = f"CS-2026-{new_num:04d}"
            
            # 4. Insert into database
            submitted_by = auth.get_current_username() if auth.is_authenticated() else None
            db.create_case(
                case_id=case_id,
                citizen_name=citizen_name,
                complaint_desc=complaint_desc,
                category=predicted_category,
                severity_score=severity_score,
                risk_score=risk_score,
                priority=priority,
                status="Open",
                sms_text=sms_text,
                email_text=email_text,
                fraud_url=fraud_url,
                transaction_details=transaction_details,
                phone_number=phone_number,
                social_media_username=social_media_username,
                submitted_by=submitted_by
            )
            
            # Insert parsed evidence entities
            if phone_number:
                db.add_evidence(case_id, "Phone Number", phone_number, "Citizen reported suspect contact")
            if fraud_url:
                db.add_evidence(case_id, "URL", fraud_url, "Citizen reported phishing URL")
            if social_media_username:
                db.add_evidence(case_id, "Social Media Handle", social_media_username, "Citizen reported suspect profile")
            if transaction_details:
                # Add Bank details if present
                bank_match = re.search(r'\b(SBI|HDFC|ICICI|Axis|Paytm|Kotak|PNB)\b', transaction_details, re.IGNORECASE)
                bank_val = bank_match.group(1).upper() + " Account" if bank_match else "Bank Account"
                db.add_evidence(case_id, "Bank Account", transaction_details[:50], "Citizen reported payment account details")

            st.balloons()
            
            st.markdown(f"""
            <div class='glowing-alert' style='background: rgba(13, 148, 136, 0.15); border-left-color: #0d9488;'>
                <h3 style='color: #0d9488; margin-top: 0;'>🛡️ Complaint Submitted Successfully!</h3>
                <p>Your Complaint has been registered in the police central directory.</p>
                <table style='width: 100%; border: none;'>
                    <tr>
                        <td><strong>Generated Case ID:</strong></td>
                        <td><span class='evidence-terminal' style='padding: 2px 8px; font-size: 1.1rem;'>{case_id}</span></td>
                    </tr>
                    <tr>
                        <td><strong>Assigned Category:</strong></td>
                        <td><span style='background: #1e293b; padding: 4px 10px; border-radius: 6px;'>{predicted_category}</span></td>
                    </tr>
                    <tr>
                        <td><strong>Auto-Assigned Priority:</strong></td>
                        <td><span class='priority-badge-{priority.lower()}'>{priority}</span></td>
                    </tr>
                </table>
                <p style='margin-bottom: 0; margin-top: 10px; font-size: 0.9rem; color: #a1a1aa;'>Please save your Case ID for future follow-up. An officer will be assigned shortly.</p>
            </div>
            """, unsafe_allow_html=True)


# ==========================================
# CITIZEN: MY CASES TRACKER
# ==========================================
def _render_my_cases():
    username = auth.get_current_username()
    my_cases = db.get_citizen_cases(username)
    st.subheader("My Filed Complaints")
    if my_cases.empty:
        st.info("You have not filed any complaints yet.")
    else:
        for _, row in my_cases.iterrows():
            priority_color = '#ef4444' if row['priority'] == 'High' else '#f59e0b' if row['priority'] == 'Medium' else '#3b82f6'
            st.markdown(f"""
            <div class="cyber-card" style="border-left: 5px solid {priority_color};">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <span style="font-size: 1.1rem; font-weight: 700; color: #ffffff;">{row['case_id']}</span>
                    <span>
                        <span class="priority-badge-{row['priority'].lower()}">{row['priority']}</span>
                        <span class="status-badge-{row['status'].lower().replace(' ', '')}">{row['status']}</span>
                    </span>
                </div>
                <div style="margin-top: 8px; font-size: 0.9rem;">
                    <strong>Category:</strong> <span style="color:#38bdf8;">{row['category']}</span> |
                    <strong>Officer:</strong> {row['officer_name']} |
                    <strong>Filed:</strong> {row['created_at']}
                </div>
                <p style="margin-top: 8px; color:#cbd5e1; font-style:italic;">"{row['complaint_desc'][:150]}..."</p>
            </div>
            """, unsafe_allow_html=True)


# ==========================================
# OFFICER CONTROL ROOM
# ==========================================
def render_officer_portal():
    st.markdown("<h1>🛡️ CyberShield Police Command Center</h1>", unsafe_allow_html=True)
    st.markdown("<p style='color:#a1a1aa;'>AI-Powered Cybercrime Intelligence & Operations Console (Law Enforcement Access Only)</p>", unsafe_allow_html=True)

    # Secondary Navigation Sidebar
    officer_tab = st.sidebar.radio(
        "Operational Modules",
        [
            "📊 Executive Dashboard",
            "🗂️ Case Management Board",
            "🔍 Cyber Crime Complaint Analyzer",
            "💬 Scam Message Detector",
            "🔗 Phishing URL Forensic Lab",
            "👤 Suspect Intelligence Network",
            "🤖 AI Legal & Forensic Assistant"
        ]
    )

    df_cases = db.get_all_cases()

    # RBAC: Officers see only their assigned cases in case management
    role = auth.get_current_role()
    username = auth.get_current_username()
    if role == "officer":
        assigned_ids = db.get_officer_assigned_cases(username)
        if assigned_ids:
            df_cases_filtered = df_cases[df_cases["case_id"].isin(assigned_ids)]
        else:
            df_cases_filtered = df_cases.head(0)
    else:
        df_cases_filtered = df_cases

    df_suspects = db.get_suspect_intelligence()

    _render_officer_tabs(officer_tab, df_cases, df_cases_filtered, df_suspects)


def _render_officer_tabs(officer_tab, df_cases, df_cases_filtered, df_suspects):
    """Shared tab content renderer used by both officer and admin portals."""
    # ----------------------------------------------------
    # TAB 1: EXECUTIVE DASHBOARD (Modules 7, 9 & 10)
    # ----------------------------------------------------
    if officer_tab == "📊 Executive Dashboard":
        st.subheader("Operations Overview")
        
        # Metric Rows
        total_complaints = len(df_cases)
        active_cases = len(df_cases[df_cases["status"] != "Closed"])
        escalated_cases = len(df_cases[df_cases["status"] == "Escalated"])
        
        # Calculate sum of fraud amounts
        total_amt = 0
        for desc in df_cases["complaint_desc"].tolist() + df_cases["transaction_details"].tolist():
            total_amt += parse_transaction_amount(desc)
            
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.metric("Total Filed Complaints", total_complaints)
        with m2:
            st.metric("Active Investigations", active_cases)
        with m3:
            st.metric("Escalated Threats", escalated_cases)
        with m4:
            st.metric("Total Tracked Financial Theft", f"Rs. {total_amt:,.2f}")

        col_left, col_right = st.columns(2)

        with col_left:
            st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
            st.subheader("Cybercrime Categories Distribution")
            if not df_cases.empty:
                cat_counts = df_cases["category"].value_counts().reset_index()
                cat_counts.columns = ["Category", "Count"]
                fig1 = px.bar(
                    cat_counts, x="Count", y="Category", orientation="h",
                    color="Count", color_continuous_scale="Viridis",
                    template="plotly_dark", height=320
                )
                fig1.update_layout(margin=dict(l=20, r=20, t=20, b=20), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
                st.plotly_chart(fig1, use_container_width=True)
            else:
                st.info("No case files registered.")
            st.markdown("</div>", unsafe_allow_html=True)

        with col_right:
            st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
            st.subheader("Cyber Risk Heatmap (Category vs Risk Matrix)")
            if not df_cases.empty:
                # Generate category vs priority heatmap matrix
                matrix_df = pd.crosstab(df_cases['category'], df_cases['priority']).reindex(columns=['Low', 'Medium', 'High'], fill_value=0)
                fig2 = px.imshow(
                    matrix_df,
                    labels=dict(x="Assigned Priority", y="Crime Category", color="Count"),
                    color_continuous_scale="Plasma",
                    template="plotly_dark", height=320
                )
                fig2.update_layout(margin=dict(l=20, r=20, t=20, b=20), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
                st.plotly_chart(fig2, use_container_width=True)
            else:
                st.info("No heatmap data available.")
            st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
        st.subheader("Scam Trends & Intelligence Feeds")
        
        c_trend, c_stats = st.columns([2, 1])
        with c_trend:
            if not df_cases.empty:
                # Sort and build dates
                df_cases["date_only"] = df_cases["created_at"].apply(lambda x: x.split(" ")[0])
                trend_df = df_cases.groupby("date_only").size().reset_index(name="Complaints")
                fig_trend = px.line(
                    trend_df, x="date_only", y="Complaints", markers=True,
                    title="Daily Incident Filing Volumes",
                    template="plotly_dark", height=240
                )
                fig_trend.update_layout(margin=dict(l=20, r=20, t=30, b=20), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
                st.plotly_chart(fig_trend, use_container_width=True)
            else:
                st.info("No trend data.")
        with c_stats:
            st.markdown("##### High-Risk Suspect Entities")
            if not df_suspects.empty:
                top_sus = df_suspects[df_suspects["linked_cases_count"] > 1].head(5)
                if not top_sus.empty:
                    st.write(top_sus[["evidence_type", "evidence_value", "linked_cases_count"]])
                else:
                    st.write("No repeat suspect entities flagged yet.")
            else:
                st.write("No evidence loaded in database.")
        st.markdown("</div>", unsafe_allow_html=True)

    # ----------------------------------------------------
    # TAB 2: CASE MANAGEMENT BOARD (Module 6)
    # ----------------------------------------------------
    elif officer_tab == "🗂️ Case Management Board":
        st.subheader("Incident Case files")
        
        # Priority filter tabs
        filter_priority = st.selectbox("Filter Priority", ["All", "High", "Medium", "Low"])
        filter_status = st.selectbox("Filter Status", ["All", "Open", "Under Investigation", "Escalated", "Closed"])
        
        df_filtered = df_cases_filtered.copy()
        if filter_priority != "All":
            df_filtered = df_filtered[df_filtered["priority"] == filter_priority]
        if filter_status != "All":
            df_filtered = df_filtered[df_filtered["status"] == filter_status]
            
        # Draw a beautiful summary table
        if df_filtered.empty:
            st.info("No cases matching the selected filters.")
        else:
            # Custom rendering
            for idx, row in df_filtered.iterrows():
                # Check for repeat offender details
                has_repeat_offender = False
                match_desc = ""
                linked_cases_list = []
                
                # Check phone
                if row["phone_number"] and row["phone_number"].strip() != "":
                    matches = db.get_linked_cases_by_entity("Phone Number", row["phone_number"])
                    linked_cases_list += [m["case_id"] for m in matches if m["case_id"] != row["case_id"]]
                if row["fraud_url"] and row["fraud_url"].strip() != "":
                    matches = db.get_linked_cases_by_entity("URL", row["fraud_url"])
                    linked_cases_list += [m["case_id"] for m in matches if m["case_id"] != row["case_id"]]

                if len(linked_cases_list) > 0:
                    has_repeat_offender = True
                    match_desc = f"🚨 REPEAT OFFENDER WARNING: Posing entity is linked to other cases: {', '.join(set(linked_cases_list))}"
                
                # Build HTML Card
                st.markdown(f"""
                <div class="cyber-card" style="border-left: 5px solid {'#ef4444' if row['priority'] == 'High' else '#f59e0b' if row['priority'] == 'Medium' else '#3b82f6'};">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="font-size: 1.15rem; font-weight: 700; color: #ffffff;">{row['case_id']} - {row['citizen_name']}</span>
                        <span>
                            <span class="priority-badge-{row['priority'].lower()}">{row['priority']}</span>
                            <span class="status-badge-{row['status'].lower().replace(' ', '')}">{row['status']}</span>
                        </span>
                    </div>
                    <div style="margin-top: 10px; font-size: 0.95rem;">
                        <strong>Crime Category:</strong> <span style="color:#38bdf8;">{row['category']}</span> | 
                        <strong>Risk Score:</strong> <span style="color:#f87171; font-weight:bold;">{row['risk_score']:.1f}/10</span> | 
                        <strong>Assigned Officer:</strong> <span style="color:#e2e8f0;">{row['officer_name']}</span> | 
                        <strong>Date:</strong> <span style="color:#a1a1aa;">{row['created_at']}</span>
                    </div>
                    <p style="margin-top: 10px; color:#cbd5e1; font-style:italic;">"{row['complaint_desc']}"</p>
                    {f'<div class="warning-alert" style="margin: 8px 0 0 0; padding: 6px 12px; font-size: 0.85rem; font-weight:600;">{match_desc}</div>' if has_repeat_offender else ''}
                </div>
                """, unsafe_allow_html=True)
                
            st.markdown("---")
            st.subheader("Manage Case File")
            
            selected_case_id = st.selectbox("Select Case ID to Update / Investigate", df_filtered["case_id"].tolist())
            case_data = db.get_case_by_id(selected_case_id)
            
            if case_data:
                col_left, col_right = st.columns(2)
                with col_left:
                    new_status = st.selectbox(
                        "Update Case Status", 
                        ["Open", "Under Investigation", "Escalated", "Closed"], 
                        index=["Open", "Under Investigation", "Escalated", "Closed"].index(case_data["status"])
                    )
                    assigned_officer = st.text_input("Assigned Investigating Officer", value=case_data["officer_name"])
                with col_right:
                    notes = st.text_area("Investigation Notes / Action Log", value=case_data["investigation_notes"], height=100)
                
                if st.button("Update Case Records", type="primary"):
                    db.update_case_status(selected_case_id, new_status, assigned_officer, notes)
                    auth.audit_case_update(selected_case_id, f"Status: {new_status}, Officer: {assigned_officer}")
                    st.success(f"Case {selected_case_id} has been updated successfully!")
                    st.rerun()

    # ----------------------------------------------------
    # TAB 3: COMPLAINT ANALYZER (Module 1)
    # ----------------------------------------------------
    elif officer_tab == "🔍 Cyber Crime Complaint Analyzer":
        st.subheader("Ad-hoc Complaint NLP Analyzer")
        st.write("Input a complaint description below to perform legal, category, and severity classification using trained NLP pipelines.")
        
        sample_complaint = st.text_area("Paste Complaint Description", height=150)
        
        if st.button("Analyze Complaint", type="primary"):
            if not sample_complaint:
                st.error("Please paste some text to analyze.")
            else:
                # 1. NLP Pred
                if "comp_model" in models and "comp_vec" in models:
                    vec = models["comp_vec"].transform([sample_complaint])
                    category = models["comp_model"].predict(vec)[0]
                else:
                    category = "UPI Fraud"
                
                # 2. Risk scoring details
                base_sev = calculate_severity_base(category)
                amount = parse_transaction_amount(sample_complaint)
                monetary_mod = min(1.5, amount / 50000.0)
                urgency_mod = 0.5 if any(w in sample_complaint.lower() for w in ["urgent", "immediately", "block", "cut", "threat", "arrest"]) else 0.0
                
                sev_score = min(10.0, base_sev + monetary_mod + urgency_mod)
                risk_score = sev_score # Default without links
                priority = "High" if risk_score >= 7.5 else "Medium" if risk_score >= 5.0 else "Low"
                
                # 3. Output
                st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
                st.write(f"### Results for NLP Intake Scan")
                
                res_col1, res_col2 = st.columns(2)
                with res_col1:
                    st.write(f"**Predicted Crime Category:** `{category}`")
                    st.write(f"**Severity Score:** `{sev_score:.1f} / 10`")
                with res_col2:
                    st.write(f"**Risk Score:** `{risk_score:.1f} / 10`")
                    st.markdown(f"**Priority:** <span class='priority-badge-{priority.lower()}'>{priority}</span>", unsafe_allow_html=True)
                
                st.write("#### Extracted Financial Metrics")
                st.write(f"- Identified Transaction Amount: **Rs. {amount:,.2f}**")
                st.write(f"- Base Class Severity: **{base_sev:.1f}/10**")
                st.write(f"- Urgency Modifier Applied: **+{urgency_mod:.1f}**")
                st.write(f"- Monetary Modifier Applied: **+{monetary_mod:.1f}**")
                st.markdown("</div>", unsafe_allow_html=True)

    # ----------------------------------------------------
    # TAB 4: SCAM MESSAGE DETECTOR (Module 2)
    # ----------------------------------------------------
    elif officer_tab == "💬 Scam Message Detector":
        st.subheader("SMS / WhatsApp / Message Forensic Scanner")
        st.write("Evaluate incoming texts, SMS, or WhatsApp threads for scam probability and urgent threats.")
        
        msg_text = st.text_area("Paste message contents", height=100)
        
        if st.button("Perform SMS Forensic Check"):
            if not msg_text:
                st.error("Please enter message text.")
            else:
                # Run ML models
                if "scam_model" in models and "scam_vec" in models:
                    vec = models["scam_vec"].transform([msg_text])
                    prob = models["scam_model"].predict_proba(vec)[0]
                    # Class order: ham, scam
                    classes = models["scam_model"].classes_
                    scam_idx = list(classes).index("scam")
                    scam_prob = prob[scam_idx]
                else:
                    scam_prob = 0.85 # Fallback
                
                # Check for threats/urgency/fraud keywords
                urgent_words = [w for w in ["urgent", "immediately", "block", "suspended", "today", "now", "verify"] if w in msg_text.lower()]
                threat_words = [w for w in ["court", "police", "arrest", "fine", "disconnect", "penalty"] if w in msg_text.lower()]
                fraud_keywords = [w for w in ["lottery", "won", "kbc", "gift", "cashback", "salary", "bonus", "loan"] if w in msg_text.lower()]
                links_found = re.findall(r'https?://[^\s]+', msg_text)
                
                # Scam Category prediction
                predicted_category = "General Scam"
                if any(w in msg_text.lower() for w in ["kbc", "lottery", "draw", "won"]):
                    predicted_category = "Lottery Scam"
                elif any(w in msg_text.lower() for w in ["kyc", "card", "sbi", "bank", "netbanking"]):
                    predicted_category = "Banking Phishing"
                elif any(w in msg_text.lower() for w in ["job", "salary", "part time", "part-time", "like"]):
                    predicted_category = "Job Task Scam"
                elif any(w in msg_text.lower() for w in ["loan", "credit", "approved"]):
                    predicted_category = "Loan App Scam"
                elif any(w in msg_text.lower() for w in ["electricity", "bill", "power", "customs", "fedex"]):
                    predicted_category = "Delivery / Utility Bill Scam"

                st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
                st.subheader("Forensic Result Summary")
                
                st.write(f"**Scam Probability:** `{scam_prob * 100:.1f}%`")
                st.write(f"**Predicted Category:** `{predicted_category}`")
                
                st.write("#### Text Analysis Flags")
                st.write(f"- **Urgency Language Markers:** {f', '.join(urgent_words) if urgent_words else 'None'}")
                st.write(f"- **Threat Language Markers:** {f', '.join(threat_words) if threat_words else 'None'}")
                st.write(f"- **Scam/Fraud Keywords:** {f', '.join(fraud_keywords) if fraud_keywords else 'None'}")
                st.write(f"- **Extracted Suspicious Links:** {f', '.join(links_found) if links_found else 'None'}")
                
                st.markdown("#### Evidence Report (Ready for Case file)")
                report_text = f"""--- DIGITAL EVIDENCE REPORT ---
Incident Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Analysis Type: SMS/WhatsApp Forensic
Scam Confidence: {scam_prob * 100:.1f}%
Inferred Scam Category: {predicted_category}
Detected Risk Markers: Urgency: {len(urgent_words)}, Threats: {len(threat_words)}, Fraud words: {len(fraud_keywords)}
Extracted Links: {links_found if links_found else 'None'}
Message text: "{msg_text}"
---------------------------------"""
                st.markdown(f"<div class='evidence-terminal'>{report_text}</div>", unsafe_allow_html=True)
                st.markdown("</div>", unsafe_allow_html=True)

    # ----------------------------------------------------
    # TAB 5: PHISHING URL FORENSIC LAB (Module 3)
    # ----------------------------------------------------
    elif officer_tab == "🔗 Phishing URL Forensic Lab":
        import json
        st.subheader("Digital Phishing Analysis Laboratory")
        st.write("Enter an address (URL) to run structural, domain, and ML forensic checks.")
        
        # Expander for Admin Retraining Panel
        with st.expander("🛠️ Model Management & Retraining Admin Panel"):
            st.markdown("### Forensic Model Control Panel")
            
            # Show active model metrics if available
            metrics_path = "models/phishing_metrics.json"
            if os.path.exists(metrics_path):
                try:
                    with open(metrics_path, "r") as f:
                        metrics_data = json.load(f)
                    
                    st.write(f"**Current Active Model:** `{metrics_data.get('best_model_name', 'Unknown')}`")
                    
                    # Columns for metrics
                    best_model_name = metrics_data.get('best_model_name', '')
                    model_metrics = metrics_data.get('models', {}).get(best_model_name, {})
                    
                    col1, col2, col3, col4 = st.columns(4)
                    col1.metric("Accuracy", f"{model_metrics.get('accuracy', 0.0)*100:.2f}%")
                    col2.metric("Precision", f"{model_metrics.get('precision', 0.0)*100:.2f}%")
                    col3.metric("Recall", f"{model_metrics.get('recall', 0.0)*100:.2f}%")
                    col4.metric("F1 Score", f"{model_metrics.get('f1', 0.0)*100:.2f}%")
                    
                    st.write("**Dataset Composition:**")
                    stats = metrics_data.get('dataset_statistics', {})
                    st.write(f"- Total Valid Records: `{stats.get('total_records', 0)}`")
                    st.write(f"- Benign URLs: `{stats.get('benign_count', 0)}` ({stats.get('benign_percentage', 0.0):.2f}%)")
                    st.write(f"- Phishing URLs: `{stats.get('phishing_count', 0)}` ({stats.get('phishing_percentage', 0.0):.2f}%)")
                except Exception as e:
                    st.warning(f"Could not load model metrics: {e}")
            else:
                st.info("No active model metrics file found. Retrain the model below to generate metrics.")
                
            st.markdown("---")
            st.write("#### Trigger Repeatable Retraining Pipeline")
            dataset_input = st.text_input("Dataset File Path", value="datasets/Training.parquet")
            
            if st.button("Execute Model Retraining"):
                if not os.path.exists(dataset_input):
                    st.error(f"Dataset path not found: {dataset_input}")
                else:
                    progress_bar = st.progress(0.0)
                    status_text = st.empty()
                    
                    def update_streamlit_progress(current, total):
                        pct = current / total
                        progress_bar.progress(pct)
                        status_text.text(f"Extracting features: {current}/{total} URLs ({pct*100:.1f}%)")
                        
                    with st.spinner("Extracting features, splitting, and training models..."):
                        try:
                            new_metrics = train_and_evaluate(dataset_input, progress_callback=update_streamlit_progress)
                            st.success(f"Successfully retrained model! Best model: **{new_metrics['best_model_name']}**")
                            # Reload models in-memory
                            st.cache_resource.clear()
                            st.rerun()
                        except Exception as ex:
                            st.error(f"Retraining failed: {ex}")
                            
        st.write("#### Analyze Suspicious URL")
        test_url = st.text_input("Analyze URL", value="http://secure-sbi-login.net/login.php")
        
        if st.button("Perform URL Forensics"):
            if not test_url:
                st.error("Please enter a URL.")
            else:
                # 1. Extract features
                features = extract_url_features(test_url)
                
                # 2. Get ML probability
                if "phish_model" in models and models["phish_model"] is not None:
                    try:
                        prob = models["phish_model"].predict_proba([features])[0]
                        classes = models["phish_model"].classes_
                        if 1 in classes:
                            phish_idx = list(classes).index(1)
                        elif "phishing" in classes:
                            phish_idx = list(classes).index("phishing")
                        else:
                            phish_idx = 1
                        ml_prob = prob[phish_idx]
                    except Exception:
                        ml_prob = 0.50
                else:
                    ml_prob = 0.50
                    
                # 3. Execute hybrid engine
                brief = run_hybrid_forensics(test_url, ml_prob)
                
                # Extract values from brief
                orig_url = brief["original_url"]
                norm_url = brief["normalized_url"]
                parsed_dict = brief["parsed_url"]
                reg_domain = brief["registered_domain"]
                is_whitelisted = brief["is_whitelisted"]
                components = brief["components"]
                rules_triggered = brief["rules_triggered"]
                risk_percentage = brief["risk_percentage"]
                threat_level = brief["threat_level"]
                recommended_action = brief["recommended_action"]
                
                # Set badge styles
                if threat_level == "Safe":
                    badge_style = "background-color: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4);"
                elif threat_level == "Low Risk":
                    badge_style = "background-color: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.4);"
                elif threat_level == "Suspicious":
                    badge_style = "background-color: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4);"
                elif threat_level == "High Risk":
                    badge_style = "background-color: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4);"
                else:
                    badge_style = "background-color: rgba(220, 38, 38, 0.25); color: #f87171; border: 1px solid #ef4444; box-shadow: 0 0 10px rgba(239, 68, 68, 0.3);"
                    
                # Generate investigation notes based on components
                notes = []
                if is_whitelisted:
                    notes.append("🟢 **Domain Reputation:** Registered domain matches a whitelisted trusted domain.")
                elif components["brand_spoof_score"] >= 0.70:
                    notes.append(f"❌ **Domain Reputation:** BRAND SPOOFING DETECTED! Similarity: **{components['brand_spoof_score']*100:.1f}%**")
                else:
                    notes.append("🟡 **Domain Reputation:** Untrusted domain (not in whitelist, no direct brand match).")
                    
                if components["protocol_score"] == 0.0:
                    notes.append("🟢 **Transport Security:** Secure Transport Layer (HTTPS) is active.")
                elif components["protocol_score"] == 0.5:
                    notes.append("❌ **Transport Security:** MISSING HTTPS! Plaintext HTTP transport detected.")
                else:
                    notes.append("❌ **Transport Security:** MALFORMED PROTOCOL ANOMALY! Protocol prefix is malformed.")
                    
                if features[6] > 0:
                    notes.append("❌ **Hostname Format:** URL uses raw IP address instead of domain hostname.")
                else:
                    notes.append("🟢 **Hostname Format:** Standard domain hostname format.")
                    
                if features[11] > 0:
                    notes.append(f"❌ **Keywords Scan:** Detected {int(features[11])} suspicious harvesting keywords.")
                else:
                    notes.append("🟢 **Keywords Scan:** No phishing keywords found.")
                    
                if features[10] > 4.2:
                    notes.append(f"❌ **Entropy Scan:** High domain character entropy ({features[10]:.2f}). Potential algorithmically generated domain (DGA).")
                else:
                    notes.append(f"🟢 **Entropy Scan:** Normal domain character entropy ({features[10]:.2f}).")
                    
                if "xn--" in parsed_dict["hostname"].lower():
                    notes.append("❌ **Unicode Scan:** IDN Homograph unicode obfuscation detected.")
                    
                # Evidence Summary
                evidence_summary = f"""--- DIGITAL FORENSIC SITE ANALYSIS REPORT ---
Time of Analysis: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Original URL: {orig_url}
Normalized URL: {norm_url}
Registered Domain: {reg_domain}
ML Classifier Score: {components['ml_score']*100:.1f}%
Final Hybrid Risk: {risk_percentage:.1f}%
Inferred Threat Level: {threat_level.upper()}

5-Component Contribution Vectors:
- Protocol Validation: {components['protocol_score']*100:.1f}%
- Forensic Rule Engine: {components['rule_score']*100:.1f}%
- Brand Similarity: {components['brand_spoof_score']*100:.1f}%
- Domain Reputation: {components['reputation_score']*100:.1f}%
- ML Model Probability: {components['ml_score']*100:.1f}%

Structural Evidence Vector:
- URL Length: {features[0]}
- Domain Length: {features[1]}
- Dots: {features[2]} | Hyphens: {features[3]}
- Subdomains: {features[9]} | Entropy: {features[10]:.2f}
- Path Length: {features[8]} | Keywords: {features[11]}
---------------------------------------------"""

                # Render Brief Card
                st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
                st.subheader("Phishing Investigation Brief")
                
                st.markdown(f"""
                <div style='display: flex; gap: 15px; align-items: center; margin-bottom: 20px;'>
                    <div style='{badge_style} padding: 5px 15px; border-radius: 9999px; font-weight: 700; font-size: 1.1rem;'>
                        THREAT LEVEL: {threat_level.upper()}
                    </div>
                    <div style='font-size: 1.1rem;'>
                        Final Risk Score: <strong style='color: #ffffff;'>{risk_percentage:.1f}%</strong>
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                col_left, col_right = st.columns(2)
                with col_left:
                    st.write("#### 🔍 Triggered Forensic Rules")
                    if rules_triggered:
                        for rule in rules_triggered:
                            st.markdown(rule)
                    else:
                        st.success("🟢 No phishing rules triggered.")
                        
                    st.write("#### 📝 Forensic Investigation Notes")
                    for n in notes:
                        st.markdown(n)
                        
                    st.write("#### 🛡️ Recommended Enforcement Action")
                    st.info(recommended_action)
                    
                with col_right:
                    st.write("#### 📊 5-Component Forensic Contribution")
                    
                    st.write(f"Protocol Validation ({components['protocol_score']*100:.0f}%)")
                    st.progress(float(components["protocol_score"]))
                    
                    st.write(f"Forensic Rules ({components['rule_score']*100:.0f}%)")
                    st.progress(float(components["rule_score"]))
                    
                    st.write(f"Brand Similarity ({components['brand_spoof_score']*100:.0f}%)")
                    st.progress(float(components["brand_spoof_score"]))
                    
                    st.write(f"Domain Reputation ({components['reputation_score']*100:.0f}%)")
                    st.progress(float(components["reputation_score"]))
                    
                    st.write(f"ML Classifier ({components['ml_score']*100:.0f}%)")
                    st.progress(float(components["ml_score"]))
                    
                    st.write("#### 📄 Digital Forensic Evidence Summary")
                    st.markdown(f"<div class='evidence-terminal'>{evidence_summary}</div>", unsafe_allow_html=True)
                st.markdown("</div>", unsafe_allow_html=True)

    # ----------------------------------------------------
    # TAB 6: SUSPECT INTELLIGENCE NETWORK (Module 5)
    # ----------------------------------------------------
    elif officer_tab == "👤 Suspect Intelligence Network":
        st.subheader("Suspect Relationship Mapping & Repeat Offenders")
        st.write("Analyze and visualize correlations between telephone numbers, UPI addresses, URLs, and case files.")
        
        # 1. Show Repeat Offender List
        st.markdown("#### Registered Suspect Entity Statistics")
        st.dataframe(df_suspects)
        
        # 2. Draw Network Relationship Graph
        st.markdown("#### Interactive Correlation Graph")
        
        df_all_ev = db.get_all_evidence()
        if not df_all_ev.empty:
            # Build network graph
            G = nx.Graph()
            
            # Nodes: Cases & Entities
            # Edges: Case <-> Entity
            for idx, row in df_all_ev.iterrows():
                case_node = row["case_id"]
                entity_node = f"{row['evidence_type']}: {row['evidence_value']}"
                
                G.add_node(case_node, type="case")
                G.add_node(entity_node, type="suspect", val=row['evidence_value'], ev_type=row['evidence_type'])
                G.add_edge(case_node, entity_node)
                
            # Get layout
            pos = nx.spring_layout(G, k=0.5, iterations=50)
            
            edge_x = []
            edge_y = []
            for edge in G.edges():
                x0, y0 = pos[edge[0]]
                x1, y1 = pos[edge[1]]
                edge_x.append(x0)
                edge_x.append(x1)
                edge_x.append(None)
                edge_y.append(y0)
                edge_y.append(y1)
                edge_y.append(None)
                
            edge_trace = go.Scatter(
                x=edge_x, y=edge_y,
                line=dict(width=1, color='#475569'),
                hoverinfo='none',
                mode='lines'
            )
            
            node_x = []
            node_y = []
            node_text = []
            node_color = []
            node_size = []
            
            for node in G.nodes():
                x, y = pos[node]
                node_x.append(x)
                node_y.append(y)
                
                node_info = G.nodes[node]
                if node_info["type"] == "case":
                    node_text.append(f"Case File: {node}")
                    node_color.append("#06b6d4") # Blue for Cases
                    node_size.append(18)
                else:
                    node_text.append(f"{node_info['ev_type']}: {node_info['val']}")
                    # If this suspect is linked to multiple cases, paint red
                    links = len(list(G.neighbors(node)))
                    if links > 1:
                        node_color.append("#ef4444") # Red for repeat offender
                        node_size.append(24)
                        node_text[-1] += f" (LINKED TO {links} CASES)"
                    else:
                        node_color.append("#fbbf24") # Orange for single suspect
                        node_size.append(14)
            
            node_trace = go.Scatter(
                x=node_x, y=node_y,
                mode='markers+text',
                hoverinfo='text',
                text=[n.split(":")[-1] for n in G.nodes()], # Display brief labels on graph
                textposition="bottom center",
                marker=dict(
                    showscale=False,
                    color=node_color,
                    size=node_size,
                    line=dict(width=2, color='#ffffff')
                )
            )
            
            fig_graph = go.Figure(
                data=[edge_trace, node_trace],
                layout=go.Layout(
                    title="Intelligence Relations Matrix (Cyan=Cases, Yellow=Suspects, Red=Repeat Suspects)",
                    template="plotly_dark",
                    showlegend=False,
                    hovermode='closest',
                    margin=dict(b=20, l=5, r=5, t=40),
                    xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                    yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
                )
            )
            
            st.plotly_chart(fig_graph, use_container_width=True)
        else:
            st.info("No suspect links established yet.")

    # ----------------------------------------------------
    # TAB 7: AI FORENSIC ASSISTANT (Module 8)
    # ----------------------------------------------------
    elif officer_tab == "🤖 AI Legal & Forensic Assistant":
        st.subheader("AI Automated Case Investigation Briefing")
        st.write("Generates comprehensive case summaries, legal sections (IPC/IT Act), evidence collections, and investigation logs.")
        
        if df_cases.empty:
            st.info("No case files registered.")
        else:
            sel_case_id = st.selectbox("Select Case ID to generate Briefing", df_cases["case_id"].tolist())
            case = db.get_case_by_id(sel_case_id)
            evidence_df = db.get_evidence_by_case(sel_case_id)
            
            if case:
                st.markdown("<div class='cyber-card'>", unsafe_allow_html=True)
                st.write(f"### CASE BRIEF: {case['case_id']}")
                st.write(f"**Citizen Name:** {case['citizen_name']} | **Incident Category:** {case['category']} | **Priority:** {case['priority']}")
                
                st.subheader("1. AI Synthesized Case Summary")
                st.write(f"The complainant, {case['citizen_name']}, reported an incident classified as {case['category']}. The details are: \"{case['complaint_desc']}\".")
                
                # Check for financial details
                amt = parse_transaction_amount(case['complaint_desc'] + case['transaction_details'])
                if amt > 0:
                    st.write(f"The total identified financial loss is estimated at **Rs. {amt:,.2f}**.")
                
                st.subheader("2. Recommended Indian Penal Code (IPC/BNS) & IT Act Sections")
                sections = generate_ipc_references(case["category"])
                for sec, desc in sections:
                    st.markdown(f"- **{sec}**: {desc}")
                
                st.subheader("3. Recommended Immediate Technical Investigations")
                if case["category"] in ["UPI Fraud", "Banking Fraud", "Investment Scam"]:
                    st.markdown("- **Bank Communication**: Draft notice under Section 91 CrPC (or Sec 94 BNSS) to the beneficiary bank to freeze the suspect accounts and retrieve transaction logs.")
                    st.markdown("- **Gateway Analysis**: Request IP address logs and registration details of the UPI transaction API.")
                elif case["category"] == "Phishing Attack" or (case["fraud_url"] and case["fraud_url"].strip() != ""):
                    st.markdown("- **Domain Takedown**: Issue warning/takedown request to domain registrar and hosting provider.")
                    st.markdown("- **DNS Investigation**: Run WHOIS Lookup to obtain administrative contact email and IP address history of the hosting server.")
                elif case["category"] in ["Sextortion", "Social Media Fraud"]:
                    st.markdown("- **Meta/Platform Request**: Issue emergency preservation request to the parent platform (Facebook/Instagram/WhatsApp) to retrieve IP logs, account creation details, and chat records of the suspect handle.")
                    st.markdown("- **Tower Location**: Request CDR (Call Detail Record) and SDR (Subscriber Detail Record) of the suspect phone number.")
                else:
                    st.markdown("- **CDR Request**: Obtain subscriber details (SDR) and call logs (CDR) of the suspects' reported phone numbers.")
                    st.markdown("- **Bank Freeze**: Request nodal officer to freeze transactions linked to the reported account.")

                st.subheader("4. Section 91 CrPC Standard Legal Notice Template")
                st.write("Copy and fill in the official notice template to request bank data:")
                
                # Parse bank names
                bank_name = "THE NODAL OFFICER, BANK/PAYMENT GATEWAY"
                bank_match = re.search(r'\b(SBI|HDFC|ICICI|Axis|Paytm|Kotak|PNB)\b', case['transaction_details'] + case['complaint_desc'], re.IGNORECASE)
                if bank_match:
                    bank_name = f"THE NODAL OFFICER, {bank_match.group(1).upper()} BANK"
                
                notice_tpl = f"""OFFICE OF THE CYBER CRIME INVESTIGATION UNIT
POLICE STATION CENTRAL ZONE, L.E.A

Reference Case ID: {case['case_id']}
Date: {datetime.now().strftime("%Y-%m-%d")}

TO,
{bank_name}
Subject: Notice under Section 91 CrPC for freezing of account and provision of transaction logs.

Sir/Madam,
It is informed that a cybercrime case has been registered under Case ID: {case['case_id']} regarding an offense under {', '.join([s[0] for s in sections])}.

During the initial digital investigation, the following suspect account/details were linked to the fraud:
- Reported Details: {case['phone_number'] if case['phone_number'] else 'N/A'} / {case['fraud_url'] if case['fraud_url'] else 'N/A'}
- Transaction Details: {case['transaction_details'] if case['transaction_details'] else 'N/A'}

You are hereby requested to:
1. Immediately freeze the beneficiary accounts linked to this transaction.
2. Provide KYC details, IP address logs of the transactions, and beneficiary account statements from {case['created_at'][:10]} onwards.

Kindly treat this on an URGENT basis.

(Signature)
Investigating Officer
Cyber Crime Police
"""
                st.markdown(f"<div class='evidence-terminal'>{notice_tpl}</div>", unsafe_allow_html=True)
                st.markdown("</div>", unsafe_allow_html=True)


# ==========================================
# LOGIN PAGE
# ==========================================
def render_login_page():
    st.markdown("""
    <div class='login-container'>
        <div class='login-header'>
            <span class='lock-icon'>🛡️</span>
            <h1>CyberShield</h1>
            <p>Police Intelligence Portal</p>
        </div>
    </div>
    """, unsafe_allow_html=True)

    col_pad1, col_form, col_pad2 = st.columns([1, 2, 1])
    with col_form:
        username = st.text_input("Username", placeholder="Enter your username", key="login_user")
        password = st.text_input("Password", type="password", placeholder="Enter your password", key="login_pass")

        if st.button("🔐 Secure Login", type="primary", use_container_width=True):
            success, message = auth.login_user(username, password)
            if success:
                st.rerun()
            else:
                st.markdown(f"<div class='login-error'>{message}</div>", unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("<p style='text-align:center; color:#64748b; font-size:0.8rem;'>Default Admin: <code>admin</code> / <code>CyberShield@2026</code><br>Default Officer: <code>insp.vikram</code> / <code>Officer@2026</code></p>", unsafe_allow_html=True)


# ==========================================
# AUTHENTICATED SIDEBAR
# ==========================================
def render_authenticated_sidebar():
    user = auth.get_current_user()
    role = user["role"]
    badge_class = f"role-badge-{role}"

    st.sidebar.markdown(f"""
    <div class='user-info-card'>
        <div class='user-name'>{user['full_name']}</div>
        <span class='{badge_class}'>{role}</span>
        <div class='user-meta'>Logged in: {user['login_time'][:16] if user['login_time'] else 'N/A'}</div>
    </div>
    """, unsafe_allow_html=True)

    if st.sidebar.button("🚪 Secure Logout", use_container_width=True):
        auth.logout_user()
        st.rerun()

    st.sidebar.markdown("---")


# ==========================================
# ADMIN PORTAL
# ==========================================
def render_admin_portal():
    st.markdown("<h1>🛡️ CyberShield Admin Command Center</h1>", unsafe_allow_html=True)

    admin_tab = st.sidebar.radio(
        "Admin Modules",
        [
            "📊 Executive Dashboard",
            "🗂️ Case Management Board",
            "🔍 Cyber Crime Complaint Analyzer",
            "💬 Scam Message Detector",
            "🔗 Phishing URL Forensic Lab",
            "👤 Suspect Intelligence Network",
            "🤖 AI Legal & Forensic Assistant",
            "👥 User Management",
            "📋 Audit Logs",
            "🔑 Case Assignments"
        ]
    )

    # Admin-only tabs
    if admin_tab == "👥 User Management":
        render_user_management()
    elif admin_tab == "📋 Audit Logs":
        render_audit_logs()
    elif admin_tab == "🔑 Case Assignments":
        render_case_assignments()
    else:
        # Reuse officer portal logic for shared operational tabs
        # We call the internals directly by simulating the tab selection
        _render_officer_tab_content(admin_tab)


def _render_officer_tab_content(officer_tab):
    """Renders officer tab content for a given tab name (used by admin portal)."""
    df_cases = db.get_all_cases()
    df_cases_filtered = df_cases  # Admin sees all
    df_suspects = db.get_suspect_intelligence()
    _render_officer_tabs(officer_tab, df_cases, df_cases_filtered, df_suspects)


def render_user_management():
    st.subheader("User Account Management")
    df_users = db.get_all_users()
    if not df_users.empty:
        st.dataframe(df_users, use_container_width=True)

    st.markdown("---")
    st.subheader("Create New User")
    col1, col2 = st.columns(2)
    with col1:
        new_username = st.text_input("Username", key="new_user")
        new_password = st.text_input("Password", type="password", key="new_pass")
    with col2:
        new_fullname = st.text_input("Full Name", key="new_name")
        new_role = st.selectbox("Role", ["citizen", "officer", "admin"], key="new_role")
    new_badge = st.text_input("Badge Number (officers only)", key="new_badge")

    if st.button("Create User", type="primary"):
        if not new_username or not new_password or not new_fullname:
            st.error("All fields are required.")
        elif db.get_user_by_username(new_username.strip().lower()):
            st.error("Username already exists.")
        else:
            hashed = auth.hash_password(new_password)
            db.create_user(new_username.strip().lower(), hashed, new_role, new_fullname, new_badge)
            auth.audit_user_created(new_username.strip().lower(), new_role)
            st.success(f"User '{new_username}' created as {new_role}!")
            st.rerun()

    st.markdown("---")
    st.subheader("Reset User Password")
    if not df_users.empty:
        reset_user = st.selectbox("Select User", df_users["username"].tolist(), key="reset_user")
        reset_pw = st.text_input("New Password", type="password", key="reset_pw")
        if st.button("Reset Password"):
            if reset_pw:
                db.update_user_password(reset_user, auth.hash_password(reset_pw))
                st.success(f"Password reset for '{reset_user}'.")


def render_audit_logs():
    st.subheader("Security Audit Trail")
    df_logs = db.get_audit_logs(500)
    if df_logs.empty:
        st.info("No audit events recorded.")
    else:
        action_filter = st.selectbox("Filter by Action", ["All"] + df_logs["action"].unique().tolist())
        if action_filter != "All":
            df_logs = df_logs[df_logs["action"] == action_filter]
        st.dataframe(df_logs, use_container_width=True)


def render_case_assignments():
    st.subheader("Case-Officer Assignment Control")
    df_assignments = db.get_case_assignments()
    if not df_assignments.empty:
        st.dataframe(df_assignments, use_container_width=True)

    st.markdown("---")
    st.subheader("Assign Officer to Case")
    df_cases = db.get_all_cases()
    df_users = db.get_all_users()
    officers = df_users[df_users["role"].isin(["officer", "admin"])]["username"].tolist() if not df_users.empty else []

    if not df_cases.empty and officers:
        assign_case = st.selectbox("Select Case", df_cases["case_id"].tolist(), key="assign_case")
        assign_officer = st.selectbox("Select Officer", officers, key="assign_officer")
        if st.button("Assign", type="primary"):
            db.assign_case_to_officer(assign_case, assign_officer, auth.get_current_username())
            db.log_audit(auth.get_current_username(), "admin", "CASE_ASSIGNED",
                         target_resource=assign_case, details=f"Assigned to {assign_officer}")
            st.success(f"Case {assign_case} assigned to {assign_officer}!")
            st.rerun()
    else:
        st.info("No cases or officers available.")



# ==========================================
# APP MAIN CONTROL FLOW
# ==========================================
def main():
    # Initialize auth session
    auth.init_session()
    auth.check_session_timeout()

    # Load CSS
    load_css()

    # Sidebar branding
    st.sidebar.markdown("<h2 style='text-align: center; color: #06b6d4; margin-bottom: 0;'>🛡️ CyberShield</h2>", unsafe_allow_html=True)
    st.sidebar.markdown("<p style='text-align: center; color: #64748b; font-size: 0.85rem; margin-top: 0;'>POLICE INTELLIGENCE PORTAL</p>", unsafe_allow_html=True)
    st.sidebar.markdown("---")

    # AUTH GATE — if not logged in, show login page only
    if not auth.is_authenticated():
        render_login_page()
        st.sidebar.markdown("<br><br>", unsafe_allow_html=True)
        st.sidebar.markdown("---")
        st.sidebar.markdown("<p style='text-align: center; color: #475569; font-size: 0.75rem;'>CyberShield v3.0 Police Edition<br>© 2026 Ministry of Law Enforcement</p>", unsafe_allow_html=True)
        return

    # AUTHENTICATED — show user info + logout in sidebar
    render_authenticated_sidebar()

    role = auth.get_current_role()

    if role == "citizen":
        render_citizen_portal()
    elif role == "officer":
        render_officer_portal()
    elif role == "admin":
        render_admin_portal()

    # Footer
    st.sidebar.markdown("<br><br>", unsafe_allow_html=True)
    st.sidebar.markdown("---")
    st.sidebar.markdown("<p style='text-align: center; color: #475569; font-size: 0.75rem;'>CyberShield v3.0 Police Edition<br>© 2026 Ministry of Law Enforcement</p>", unsafe_allow_html=True)

if __name__ == "__main__":
    main()

