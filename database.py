import sqlite3
import pandas as pd
from datetime import datetime

DB_NAME = "cybershield.db"

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create cases table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            citizen_name TEXT NOT NULL,
            complaint_desc TEXT NOT NULL,
            category TEXT NOT NULL,
            severity_score REAL NOT NULL,
            risk_score REAL NOT NULL,
            priority TEXT NOT NULL,
            status TEXT NOT NULL,
            officer_name TEXT DEFAULT 'Unassigned',
            created_at TEXT NOT NULL,
            investigation_notes TEXT DEFAULT '',
            sms_text TEXT DEFAULT '',
            email_text TEXT DEFAULT '',
            fraud_url TEXT DEFAULT '',
            transaction_details TEXT DEFAULT '',
            phone_number TEXT DEFAULT '',
            social_media_username TEXT DEFAULT ''
        )
    """)
    
    # Create evidence table for entity linking
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            evidence_value TEXT NOT NULL,
            details TEXT DEFAULT '',
            FOREIGN KEY (case_id) REFERENCES cases (case_id)
        )
    """)
    
    conn.commit()
    
    # Check if empty, and seed data for the dashboard
    cursor.execute("SELECT COUNT(*) FROM cases")
    count = cursor.fetchone()[0]
    
    if count == 0:
        print("Seeding initial mock cybercrime cases...")
        
        # Seed Cases
        mock_cases = [
            (
                "CS-2026-0001", "Rohan Sharma", 
                "Received WhatsApp QR code on scan to pay. Lost 45,000 INR from Google Pay account trying to sell an old phone.",
                "UPI Fraud", 7.5, 8.2, "High", "Under Investigation", "Insp. Vikram Rathore",
                "2026-06-15 10:30:00", "IP address tracked to Jamtara area. Transaction logs requested from Paytm Payment Bank.",
                "", "", "", "Debit of Rs. 45000 to merchant PAYTM*FRAUDSTER", "+91 98765 43210", ""
            ),
            (
                "CS-2026-0002", "Anita Desai", 
                "Got an email saying KBC Lottery winner of 25 Lakhs. Sent 15,000 registration fee to UPI ID kbc.office@icici.",
                "Lottery Scam", 4.0, 5.5, "Medium", "Open", "Unassigned",
                "2026-06-16 11:15:00", "Citizen was contacted via WhatsApp. UPI ID flagged in system.",
                "Congratulations! You won KBC lottery...", "", "", "Transfer of Rs. 15000 to kbc.office@icici", "+91 98765 43210", ""
            ),
            (
                "CS-2026-0003", "Karan Johar", 
                "Fake profile of my father created on Facebook. Hacker sent messages asking family members for medical cash emergency.",
                "Social Media Fraud", 6.0, 6.8, "Medium", "Open", "Unassigned",
                "2026-06-17 14:00:00", "Requested profile takedown from Meta. IP logs pending.",
                "", "", "", "None", "", "papa_karan_fake"
            ),
            (
                "CS-2026-0004", "Sunita Nair", 
                "Video call on WhatsApp from girl who stripped. Then threatened to leak screen recording to my friends. Demanding 50,000.",
                "Sextortion", 9.0, 9.5, "High", "Escalated", "Insp. Neha Sen",
                "2026-06-18 09:20:00", "Extreme distress reported. Mobile location shows Mewat border. Bank account freeze request sent.",
                "", "", "", "UPI transfer of Rs. 10000 sent before reporting", "+91 88888 77777", ""
            ),
            (
                "CS-2026-0005", "David Miller", 
                "Clicked a link claiming HDFC KYC update (hdfc-secure-net.info). My password was stolen and 1,20,000 INR was transferred.",
                "Phishing Attack", 8.5, 9.0, "High", "Under Investigation", "Insp. Vikram Rathore",
                "2026-06-18 16:45:00", "Cloned phishing page hosted on digitalocean. Domain registrar contacted for shutdown.",
                "", "", "http://hdfc-secure-net.info/login", "IMPS transfer of 1,20,000 to ICICI A/C 9382019382", "", ""
            ),
            (
                "CS-2026-0006", "Amit Patel", 
                "Offered part-time job on Telegram. Paid Rs 150 first, then asked to deposit 20,000 for tasks. Stole the entire money.",
                "Job Scam", 5.5, 6.2, "Medium", "Open", "Unassigned",
                "2026-06-19 12:00:00", "Telegram channel name: @EasyEarnTasks. Payment received in account: HDFC 1029381029.",
                "", "", "", "UPI debit of Rs. 20000", "+91 98765 43210", ""
            )
        ]
        
        cursor.executemany("""
            INSERT INTO cases (
                case_id, citizen_name, complaint_desc, category, severity_score, risk_score, priority, status, officer_name,
                created_at, investigation_notes, sms_text, email_text, fraud_url, transaction_details, phone_number, social_media_username
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, mock_cases)
        
        # Seed Evidence (Entities)
        # Note: +91 98765 43210 is a repeat suspect linked to CS-2026-0001, CS-2026-0002, and CS-2026-0006!
        # This will trigger our Repeat Offender Alert.
        mock_evidence = [
            ("CS-2026-0001", "Phone Number", "+91 98765 43210", "Suspect Oliver OLX buyer contact"),
            ("CS-2026-0001", "Bank Account", "Paytm PB 9081726354", "Receiving wallet bank"),
            
            ("CS-2026-0002", "Phone Number", "+91 98765 43210", "Suspect WhatsApp caller"),
            ("CS-2026-0002", "UPI ID", "kbc.office@icici", "Receiving UPI account"),
            
            ("CS-2026-0003", "Social Media Handle", "papa_karan_fake", "Fake FB account profile handle"),
            
            ("CS-2026-0004", "Phone Number", "+91 88888 77777", "Sextortion blackmailer WhatsApp number"),
            ("CS-2026-0004", "UPI ID", "mewat.helper@okaxis", "Receiving extortion UPI"),
            
            ("CS-2026-0005", "URL", "http://hdfc-secure-net.info/login", "Cloned phishing page URL"),
            ("CS-2026-0005", "Bank Account", "ICICI A/C 9382019382", "Mule bank account where funds landed"),
            
            ("CS-2026-0006", "Phone Number", "+91 98765 43210", "Telegram recruiter WhatsApp contact"),
            ("CS-2026-0006", "Bank Account", "HDFC 1029381029", "Receiving merchant bank account")
        ]
        
        cursor.executemany("""
            INSERT INTO evidence (case_id, evidence_type, evidence_value, details)
            VALUES (?, ?, ?, ?)
        """, mock_evidence)
        
        conn.commit()
    
    conn.close()

def create_case(case_id, citizen_name, complaint_desc, category, severity_score, risk_score, priority, status, 
                sms_text="", email_text="", fraud_url="", transaction_details="", phone_number="", social_media_username="", officer_name="Unassigned"):
    conn = get_db_connection()
    cursor = conn.cursor()
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    cursor.execute("""
        INSERT INTO cases (
            case_id, citizen_name, complaint_desc, category, severity_score, risk_score, priority, status, officer_name,
            created_at, sms_text, email_text, fraud_url, transaction_details, phone_number, social_media_username
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (case_id, citizen_name, complaint_desc, category, severity_score, risk_score, priority, status, officer_name,
          created_at, sms_text, email_text, fraud_url, transaction_details, phone_number, social_media_username))
    
    conn.commit()
    conn.close()

def add_evidence(case_id, evidence_type, evidence_value, details=""):
    if not evidence_value or evidence_value.strip() == "":
        return
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO evidence (case_id, evidence_type, evidence_value, details)
        VALUES (?, ?, ?, ?)
    """, (case_id, evidence_type, evidence_value.strip(), details))
    conn.commit()
    conn.close()

def get_all_cases():
    conn = get_db_connection()
    df = pd.read_sql_query("SELECT * FROM cases ORDER BY created_at DESC", conn)
    conn.close()
    return df

def get_case_by_id(case_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def update_case_status(case_id, status, officer_name, notes):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE cases 
        SET status = ?, officer_name = ?, investigation_notes = ?
        WHERE case_id = ?
    """, (status, officer_name, notes, case_id))
    conn.commit()
    conn.close()

def get_evidence_by_case(case_id):
    conn = get_db_connection()
    df = pd.read_sql_query("SELECT * FROM evidence WHERE case_id = ?", conn, params=(case_id,))
    conn.close()
    return df

def get_suspect_intelligence():
    # Find evidence entities that are linked to multiple complaints
    conn = get_db_connection()
    query = """
        SELECT evidence_type, evidence_value, COUNT(DISTINCT case_id) as linked_cases_count, GROUP_CONCAT(case_id, ', ') as case_ids
        FROM evidence
        GROUP BY evidence_type, evidence_value
        ORDER BY linked_cases_count DESC
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

def get_all_evidence():
    conn = get_db_connection()
    df = pd.read_sql_query("SELECT * FROM evidence", conn)
    conn.close()
    return df

def get_linked_cases_by_entity(entity_type, entity_value):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT DISTINCT c.* 
        FROM cases c
        JOIN evidence e ON c.case_id = e.case_id
        WHERE e.evidence_type = ? AND e.evidence_value = ?
    """, (entity_type, entity_value))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# Initialize database on import
init_db()
print("Database initialized successfully!")
