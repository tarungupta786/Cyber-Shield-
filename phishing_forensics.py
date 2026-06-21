import re
import math
from collections import Counter
from urllib.parse import urlparse

# Whitelisted trusted domains
TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "github.com", "stackoverflow.com", "wikipedia.org",
    "netflix.com", "facebook.com", "twitter.com", "linkedin.com", "instagram.com",
    "amazon.in", "amazon.com", "sbi.co.in", "hdfcbank.com", "icicibank.com",
    "yahoo.com", "microsoft.com", "reddit.com", "ycombinator.com", "gov.in", "nic.in",
    "irctc.co.in"
}

# Monitored brand list for spoofing / typo-squatting checks
MONITORED_BRANDS = {
    "google": "google.com",
    "youtube": "youtube.com",
    "github": "github.com",
    "paypal": "paypal.com",
    "sbi": "sbi.co.in",
    "hdfc": "hdfcbank.com",
    "paytm": "paytm.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "amazon": "amazon.com",
    "icici": "icicibank.com",
    "microsoft": "microsoft.com"
}

# Suspicious keywords that indicate phishing/credential harvesting
SUSPICIOUS_KEYWORDS = [
    "login", "secure", "kyc", "verify", "update", "bank", "free", "lottery",
    "cashback", "rewards", "claim", "credential", "signin", "support", "billing",
    "account", "security"
]

# Suspicious TLD list
SUSPICIOUS_TLDS = {
    ".xyz", ".ru", ".cc", ".info", ".net", ".click", ".top", ".ga", ".cf", ".gq",
    ".tk", ".ml", ".link", ".zip", ".work", ".fit", ".cn", ".buzz", ".live", ".best"
}

# Popular shorteners
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "is.gd", "buff.ly", "ow.ly", "t.co", "rebrand.ly",
    "tiny.cc", "goo.gl", "bit.do"
}

def levenshtein_distance(s1, s2):
    """Computes Levenshtein distance between s1 and s2."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
        
    return previous_row[-1]

def get_registered_domain(url):
    """Parses and returns the registered domain (e.g. google.com, amazon.co.in)."""
    try:
        # Check if URL starts with standard prefix. If not, add one for parsing
        if not url.lower().startswith(("http://", "https://")):
            parsed = urlparse("https://" + url)
        else:
            parsed = urlparse(url)
            
        hostname = parsed.hostname
        if not hostname:
            return ""
        
        hostname = hostname.lower()
        if hostname.startswith("www."):
            hostname = hostname[4:]
            
        # If it's a raw IP, return it directly
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
            return hostname
            
        parts = hostname.split(".")
        if len(parts) <= 2:
            return hostname
            
        # Handle double country-code TLDs (e.g. .co.in, .gov.in, .org.uk)
        double_tlds = {"co", "gov", "org", "com", "edu", "net", "res", "mil"}
        if parts[-2] in double_tlds and len(parts) >= 3:
            return ".".join(parts[-3:])
            
        return ".".join(parts[-2:])
    except Exception:
        return ""

def calculate_entropy(text):
    """Computes Shannon Entropy of a string."""
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def check_protocol_anomaly(url):
    """
    Checks for protocol malformations and returns:
    (anomaly_score, original_url, normalized_url, parsed_url)
    Do NOT silently normalize malformed URLs.
    """
    original_url = url
    anomaly_score = 0.0
    lower_url = url.lower()
    
    # 1. Match common malformed protocol prefixes
    malformed_patterns = [
        r"^htttps", r"^hxxps", r"^ttp", r"^httpss", r"^http[s]{2,}", r"^htps", r"^hps"
    ]
    
    is_malformed = False
    for pattern in malformed_patterns:
        if re.match(pattern, lower_url):
            is_malformed = True
            break
            
    if is_malformed:
        anomaly_score = 1.0
    elif not lower_url.startswith(("http://", "https://")):
        # Check if contains protocol-like typos anywhere without proper separators
        if any(typo in lower_url for typo in ["htttps", "hxxps", "httpss", "ttps:", "http:"]):
            anomaly_score = 1.0
            
    # Normalize URL for subsequent parsing, but preserve original_url
    normalized_url = url
    if anomaly_score > 0:
        # Strip malformed protocol prefix and force standard https://
        cleaned = re.sub(r'^(ht+ps*|hxxps*|ttps*|hp+s*)[^a-zA-Z0-9]*', '', url, flags=re.IGNORECASE)
        normalized_url = "https://" + cleaned
    else:
        if not url.startswith(("http://", "https://")):
            normalized_url = "https://" + url
            
    try:
        parsed_url = urlparse(normalized_url)
    except Exception:
        parsed_url = urlparse("https://invalid-url.com")
        
    return anomaly_score, original_url, normalized_url, parsed_url

def get_brand_spoof_details(hostname, reg_domain):
    """
    Computes Levenshtein-based brand similarity.
    Returns: (brand_similarity_score, brand_spoof_flag)
    """
    if not reg_domain or not hostname:
        return 0.0, 0
        
    # Extract domain prefix (e.g. "google" from "google.com")
    reg_prefix = reg_domain.split(".")[0].lower()
    
    max_similarity = 0.0
    brand_spoof_flag = 0
    
    # Split prefix by common word boundary delimiters
    prefix_parts = re.split(r'[-_]', reg_prefix)
    
    for brand, official_domain in MONITORED_BRANDS.items():
        # If it is indeed the official domain, it's not spoofing
        if reg_domain == official_domain or reg_domain == f"www.{official_domain}":
            continue
            
        # Rule 1: Brand name is directly contained in the registration prefix (e.g. "paypal-login")
        if brand in reg_prefix:
            max_similarity = max(max_similarity, 1.0)
            brand_spoof_flag = 1
            continue
            
        # Rule 2: Levenshtein distance check on each split part
        for part in prefix_parts:
            if not part:
                continue
            dist = levenshtein_distance(part, brand)
            max_len = max(len(part), len(brand))
            similarity = 1.0 - (dist / max_len) if max_len > 0 else 0.0
            
            # Lower threshold to 0.60 to catch character substitutions (like "g00gle" -> 66.7%)
            if similarity >= 0.60:
                brand_spoof_flag = 1
                max_similarity = max(max_similarity, similarity)
                
    return max_similarity, brand_spoof_flag

def extract_url_features(url):
    """
    Extracts 16 advanced features from raw URL.
    Ensures zero syntax failures by robustly cleaning inputs.
    """
    try:
        # 1. Protocol checking
        anomaly_score, original, normalized, parsed = check_protocol_anomaly(url)
        hostname = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        
        # 2. Whitelist checking
        reg_domain = get_registered_domain(url)
        is_whitelisted = False
        for td in TRUSTED_DOMAINS:
            if reg_domain == td or reg_domain.endswith("." + td):
                is_whitelisted = True
                break
                
        # Feature calculations
        length_url = len(url)
        length_domain = len(hostname)
        nb_dots = url.count(".")
        nb_hyphens = url.count("-")
        
        special_chars = ['@', '?', '=', '&', '_', '%']
        nb_special_chars = sum(url.count(c) for c in special_chars)
        
        # HTTPS Presence - strict check (must start with standard https://)
        is_https = 1 if url.startswith("https://") else 0
        
        # Raw IP Hostname
        has_ip = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', hostname) else 0
        
        # Query Param Count
        query_params_count = len(query.split("&")) if query else 0
        
        # Path Length
        path_length = len(path)
        
        # Subdomain count
        hostname_parts = hostname.split(".")
        reg_parts = reg_domain.split(".")
        num_subdomains = max(0, len(hostname_parts) - len(reg_parts))
        
        # Shannon Entropy
        entropy = calculate_entropy(hostname)
        
        # Suspicious Keywords
        keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url.lower())
        
        # Whitelist and Reputation flags
        domain_reputation_flag = 0.0 if is_whitelisted else 1.0
        trusted_domain_flag = 1.0 if is_whitelisted else 0.0
        
        # Brand spoof score & flag
        brand_similarity_score, brand_spoof_flag = get_brand_spoof_details(hostname, reg_domain)
        
        return [
            float(length_url),
            float(length_domain),
            float(nb_dots),
            float(nb_hyphens),
            float(nb_special_chars),
            float(is_https),
            float(has_ip),
            float(query_params_count),
            float(path_length),
            float(num_subdomains),
            float(entropy),
            float(keyword_count),
            float(domain_reputation_flag),
            float(trusted_domain_flag),
            float(brand_similarity_score),
            float(anomaly_score)
        ]
    except Exception:
        return [0.0] * 16

def run_rule_engine(url, features):
    """
    Evaluates rule indicators and returns:
    (rule_score, list_of_triggered_rules)
    """
    # Map features by index
    # 0: length_url, 1: length_domain, 2: nb_dots, 3: nb_hyphens, 4: nb_special_chars
    # 5: is_https, 6: has_ip, 7: query_params, 8: path_length, 9: subdomains
    # 10: entropy, 11: keywords, 12: reputation, 13: whitelist, 14: brand_spoof_score, 15: anomaly_score
    
    rules_triggered = []
    rule_score = 0.0
    
    # 1. Invalid Protocol
    if features[15] > 0:
        rules_triggered.append("[MALFORMED PROTOCOL] Invalid/Malformed Protocol Anomaly (e.g. htttps, hxxps)")
        rule_score += 0.25
        
    # 2. Raw IP Address
    if features[6] > 0:
        rules_triggered.append("[RAW IP] Hostname resolves directly to Raw IP Address (High Risk)")
        rule_score += 0.30
        
    # 3. Brand Spoofing
    if features[14] >= 0.70:
        rules_triggered.append(f"[BRAND SPOOFING] Brand Spoofing typosquatting detected (Similarity: {features[14]*100:.1f}%)")
        rule_score += 0.35
        
    # 4. Suspicious TLD
    reg_domain = get_registered_domain(url)
    has_susp_tld = any(reg_domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
    if has_susp_tld:
        rules_triggered.append(f"[SUSPICIOUS TLD] Suspicious Top-Level Domain (TLD) resolving")
        rule_score += 0.15
        
    # 5. Excessive Subdomains
    if features[9] > 2:
        rules_triggered.append(f"[SUBDOMAINS] Excessive subdomain layering ({int(features[9])} subdomains)")
        rule_score += 0.15
        
    # 6. Credential Harvesting Keywords
    if features[11] > 0:
        rules_triggered.append(f"[KEYWORDS] Credential/scam keywords detected in URL path ({int(features[11])} keywords)")
        rule_score += 0.15
        
    # 7. URL Shorteners
    # Get hostname
    anomaly_score, original, normalized, parsed = check_protocol_anomaly(url)
    hostname = parsed.hostname or ""
    if hostname.lower() in URL_SHORTENERS:
        rules_triggered.append("[SHORTENER] URL shortener service masking final destination")
        rule_score += 0.20
        
    # 8. Unicode Obfuscation
    if "xn--" in hostname.lower() or not all(ord(c) < 128 for c in hostname):
        rules_triggered.append("[UNICODE] Unicode IDN Homograph Obfuscation detected (non-ASCII symbols)")
        rule_score += 0.25
        
    rule_score = min(1.0, rule_score)
    return rule_score, rules_triggered

def run_hybrid_forensics(url, ml_prob):
    """
    Combines five components into a final risk score (20% each).
    - Protocol Score: 1.0 (malformed), 0.5 (HTTP), 0.0 (HTTPS)
    - Rule Score: (0.0 to 1.0)
    - Brand Spoof Score: (0.0 to 1.0)
    - Reputation Score: 1.0 (untrusted), 0.0 (whitelisted)
    - ML Probability: (0.0 to 1.0)
    """
    features = extract_url_features(url)
    reg_domain = get_registered_domain(url)
    
    anomaly_score, original, normalized, parsed = check_protocol_anomaly(url)
    hostname = parsed.hostname or ""
    
    # Check whitelist
    is_whitelisted = False
    for td in TRUSTED_DOMAINS:
        if reg_domain == td or reg_domain.endswith("." + td):
            is_whitelisted = True
            break
            
    # Component 1: Protocol Score (20%)
    # HTTPS starts with standard protocol = 0.0. Plain HTTP = 0.5. Malformed = 1.0
    if anomaly_score > 0:
        protocol_score = 1.0
    elif url.startswith("https://"):
        protocol_score = 0.0
    else:
        protocol_score = 0.5
        
    # Component 2: Rule Score (20%)
    rule_score, rules_triggered = run_rule_engine(url, features)
    
    # Component 3: Brand Spoof Score (20%)
    brand_similarity_score, brand_spoof_flag = get_brand_spoof_details(hostname, reg_domain)
    
    # Component 4: Domain Reputation Score (20%)
    reputation_score = 0.0 if is_whitelisted else 1.0
    
    # Component 5: Machine Learning Score (20%)
    ml_score = ml_prob
    if is_whitelisted:
        # Clear out any ML score false positives for whitelisted domains
        ml_score = 0.0
        brand_similarity_score = 0.0
        reputation_score = 0.0
        
    # Combine scores
    final_risk_score = (
        0.20 * protocol_score +
        0.20 * rule_score +
        0.20 * brand_similarity_score +
        0.20 * reputation_score +
        0.20 * ml_score
    )
    
    # Correlation engine adjustments
    # Brand Spoofing + Untrusted Domain + Suspicious TLD -> add 0.10 correlation bonus
    has_susp_tld = any(reg_domain.endswith(tld) for tld in SUSPICIOUS_TLDS)
    if brand_spoof_flag > 0 and not is_whitelisted and has_susp_tld:
        final_risk_score += 0.10
        
    # Final calibration override:
    # If it is whitelisted and has no protocol anomalies or rules, force minimal risk
    if is_whitelisted and protocol_score == 0.0 and rule_score == 0.0:
        final_risk_score = 0.01
        
    final_risk_score = min(1.0, max(0.0, final_risk_score))
    risk_percentage = final_risk_score * 100
    
    # Threat levels
    if risk_percentage < 10.0:
        threat_level = "Safe"
    elif risk_percentage < 20.0:
        threat_level = "Low Risk"
    elif risk_percentage < 55.0:
        threat_level = "Suspicious"
    elif risk_percentage < 87.0:
        threat_level = "High Risk"
    else:
        threat_level = "Critical"
        
    # Recommended Action
    if threat_level == "Safe":
        action = "[SAFE] Whitelisted or highly reputable domain. No security action required."
    elif threat_level == "Low Risk":
        action = "[INFO] Domain appears safe, but maintain standard vigilance."
    elif threat_level == "Suspicious":
        action = "[WARNING] Keep domain under active observation. Inspect redirects or suspicious activity logs."
    elif threat_level == "High Risk":
        action = "[ALERT] Alert cyber crime unit. Issue warning alert to personnel accessing this domain."
    else:
        action = "[IMMEDIATE ENFORCEMENT ACTION] Section 91 DNS blocking request. Initiate domain takedown protocol."
        
    return {
        "original_url": original,
        "normalized_url": normalized,
        "parsed_url": {
            "scheme": parsed.scheme,
            "netloc": parsed.netloc,
            "path": parsed.path,
            "query": parsed.query,
            "hostname": hostname
        },
        "registered_domain": reg_domain,
        "is_whitelisted": is_whitelisted,
        "features": features,
        "components": {
            "protocol_score": protocol_score,
            "rule_score": rule_score,
            "brand_spoof_score": brand_similarity_score,
            "reputation_score": reputation_score,
            "ml_score": ml_score
        },
        "rules_triggered": rules_triggered,
        "final_risk_score": final_risk_score,
        "risk_percentage": risk_percentage,
        "threat_level": threat_level,
        "recommended_action": action
    }
