import os
import pickle
import sqlite3
import joblib
from urllib.parse import urlparse
import pandas as pd

from phishing_forensics import (
    extract_url_features,
    run_hybrid_forensics,
    get_registered_domain
)

def test_database():
    print("\n[DB] Testing SQLite Database...")
    if not os.path.exists("cybershield.db"):
        print("FAIL: cybershield.db does not exist!")
        return False
        
    try:
        import database as db
        cases = db.get_all_cases()
        print(f"SUCCESS: Loaded {len(cases)} cases from database.")
        
        suspects = db.get_suspect_intelligence()
        print(f"SUCCESS: Loaded {len(suspects)} suspect records.")
        
        sample_case = db.get_case_by_id("CS-2026-0001")
        if sample_case:
            print("SUCCESS: Retrieved sample case details.")
        else:
            print("FAIL: Failed to retrieve CS-2026-0001 details.")
            return False
            
    except Exception as e:
        print(f"FAIL: Database exception occurred: {e}")
        return False
    return True

def test_models():
    print("\n[ML] Testing ML Models...")
    required_files = [
        "models/complaint_vectorizer.pkl",
        "models/complaint_model.pkl",
        "models/scam_vectorizer.pkl",
        "models/scam_model.pkl"
    ]
    
    for rf in required_files:
        if not os.path.exists(rf):
            print(f"FAIL: Model file missing: {rf}")
            return False
            
    try:
        # Load and test complaint categorizer
        with open("models/complaint_vectorizer.pkl", "rb") as f:
            cv = pickle.load(f)
        with open("models/complaint_model.pkl", "rb") as f:
            cm = pickle.load(f)
            
        test_text = "I received a QR code to scan and 25000 was debited from my UPI account"
        vec = cv.transform([test_text])
        pred = cm.predict(vec)[0]
        print(f"SUCCESS: Complaint categorizer test: '{test_text}' -> '{pred}'")
        
        # Load and test SMS scam detector
        with open("models/scam_vectorizer.pkl", "rb") as f:
            sv = pickle.load(f)
        with open("models/scam_model.pkl", "rb") as f:
            sm = pickle.load(f)
            
        test_sms = "CONGRATULATIONS you won KBC lottery of 25 lakhs click link to claim"
        vec_sms = sv.transform([test_sms])
        pred_sms = sm.predict(vec_sms)[0]
        print(f"SUCCESS: SMS scam test: '{test_sms}' -> '{pred_sms}'")
        
    except Exception as e:
        print(f"FAIL: ML Model loading/prediction exception: {e}")
        return False
    return True

def test_phishing_forensics():
    print("\n[PHISH] Testing Hybrid Phishing Forensics Engine...")
    
    # Load model (prefer joblib)
    if os.path.exists("models/phishing_model.joblib"):
        pm = joblib.load("models/phishing_model.joblib")
        print("Loaded phishing model: models/phishing_model.joblib")
    elif os.path.exists("models/phishing_model.pkl"):
        with open("models/phishing_model.pkl", "rb") as f:
            pm = pickle.load(f)
        print("Loaded phishing model: models/phishing_model.pkl")
    else:
        print("FAIL: Phishing classifier binary not found in models/ folder!")
        return False
        
    test_cases = [
        {"url": "https://www.youtube.com/results?search_query=linear+algebra+for+gate+exam", "expected": "Safe"},
        {"url": "https://google.com", "expected": "Safe"},
        {"url": "https://github.com", "expected": "Safe"},
        {"url": "htttps.MicRosoft.com", "expected": "Suspicious"},
        {"url": "http://g00gle-login.xyz", "expected": "High Risk"},
        {"url": "http://paypal-security-check.ru", "expected": "Critical"},
        {"url": "http://micr0soft.com", "expected": "High Risk"}
    ]
    
    all_passed = True
    print("\n--- Running Phishing Forensics Test Cases ---")
    for case in test_cases:
        url = case["url"]
        expected = case["expected"]
        
        # 1. Extract features
        features = extract_url_features(url)
        
        # 2. Get ML probability
        try:
            prob = pm.predict_proba([features])[0]
            classes = pm.classes_
            if 1 in classes:
                phish_idx = list(classes).index(1)
            elif "phishing" in classes:
                phish_idx = list(classes).index("phishing")
            else:
                phish_idx = 1
            ml_prob = prob[phish_idx]
        except Exception as e:
            ml_prob = 0.50
            
        # 3. Get hybrid forensics brief
        brief = run_hybrid_forensics(url, ml_prob)
        threat_level = brief["threat_level"]
        risk_pct = brief["risk_percentage"]
        rules = brief["rules_triggered"]
        
        # Validate match
        passed = (threat_level.lower() == expected.lower())
        status = "PASSED" if passed else "FAILED"
        if not passed:
            all_passed = False
            
        print(f"\nURL: {url}")
        print(f"  Expected: {expected} | Inferred: {threat_level} ({risk_pct:.1f}% Risk) | Status: {status}")
        print(f"  ML Prob: {ml_prob*100:.1f}% | Reg Domain: {brief['registered_domain']}")
        if rules:
            print(f"  Triggered Rules:")
            for r in rules:
                print(f"    - {r}")
                
    return all_passed

if __name__ == "__main__":
    db_ok = test_database()
    ml_ok = test_models()
    phish_ok = test_phishing_forensics()
    
    if db_ok and ml_ok and phish_ok:
        print("\nALL SYSTEM VERIFICATIONS PASSED! CyberShield is ready to run.")
    else:
        print("\nSYSTEM VERIFICATION FAILED! Please inspect errors above.")
