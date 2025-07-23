from flask import Flask, request, jsonify, render_template
import pandas as pd
import joblib
import re
import socket
import urllib.parse
from urllib.parse import urlparse
import requests
import whois
from datetime import datetime
import dns.resolver
import tldextract

app = Flask(__name__)

# Load trained model
model = joblib.load("model/phishing_model_decision_tree.pkl")

# Function to extract features from URL
def extract_features(url):
    """
    Extract comprehensive features from URL for phishing detection
    """
    features = {}
    
    try:
        # Parse URL
        parsed_url = urlparse(url)
        extracted = tldextract.extract(url)
        
        # Basic URL features
        features["length_url"] = len(url)
        features["length_hostname"] = len(parsed_url.netloc) if parsed_url.netloc else 0
        
        # Check if hostname is IP address
        hostname = parsed_url.netloc.split(':')[0]  # Remove port if present
        try:
            socket.inet_aton(hostname)
            features["ip"] = 1
        except socket.error:
            features["ip"] = 0
        
        # Character counts
        features["nb_dots"] = url.count('.')
        features["nb_hyphens"] = url.count('-')
        features["nb_at"] = url.count('@')
        features["nb_qm"] = url.count('?')
        features["nb_and"] = url.count('&')
        features["nb_or"] = url.count('|')
        features["nb_eq"] = url.count('=')
        features["nb_underscore"] = url.count('_')
        features["nb_tilde"] = url.count('~')
        features["nb_percent"] = url.count('%')
        features["nb_slash"] = url.count('/')
        features["nb_star"] = url.count('*')
        features["nb_colon"] = url.count(':')
        features["nb_comma"] = url.count(',')
        features["nb_semicolumn"] = url.count(';')
        features["nb_dollar"] = url.count('$')
        features["nb_space"] = url.count(' ')
        
        # Specific string counts
        features["nb_www"] = url.lower().count('www')
        features["nb_com"] = url.lower().count('com')
        features["nb_dslash"] = url.count('//')
        
        # Protocol and path features
        features["http_in_path"] = 1 if 'http' in parsed_url.path.lower() else 0
        features["https_token"] = 1 if url.lower().startswith('https') else 0
        
        # Digit ratios
        digits_in_url = sum(c.isdigit() for c in url)
        features["ratio_digits_url"] = digits_in_url / len(url) if len(url) > 0 else 0
        
        digits_in_host = sum(c.isdigit() for c in hostname)
        features["ratio_digits_host"] = digits_in_host / len(hostname) if len(hostname) > 0 else 0
        
        # Punycode detection
        features["punycode"] = 1 if 'xn--' in url.lower() else 0
        
        # Port detection
        port_match = re.search(r':(\d+)', parsed_url.netloc)
        features["port"] = 1 if port_match and port_match.group(1) not in ['80', '443'] else 0
        
        # TLD features
        features["tld_in_path"] = 1 if any(tld in parsed_url.path.lower() for tld in ['.com', '.org', '.net', '.edu', '.gov']) else 0
        features["tld_in_subdomain"] = 1 if any(tld in extracted.subdomain.lower() for tld in ['com', 'org', 'net', 'edu', 'gov']) else 0
        
        # Subdomain features
        subdomains = extracted.subdomain.split('.') if extracted.subdomain else []
        features["nb_subdomains"] = len([s for s in subdomains if s])
        features["abnormal_subdomain"] = 1 if features["nb_subdomains"] > 3 else 0
        
        # Domain name features
        domain = extracted.domain
        features["prefix_suffix"] = 1 if '-' in domain else 0
        
        # Random domain detection (basic heuristic)
        vowels = 'aeiou'
        consonants = 'bcdfghjklmnpqrstvwxyz'
        vowel_ratio = sum(1 for c in domain.lower() if c in vowels) / len(domain) if len(domain) > 0 else 0
        features["random_domain"] = 1 if vowel_ratio < 0.2 or vowel_ratio > 0.8 else 0
        
        # Shortening service detection
        shortening_services = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly', 'short.link']
        features["shortening_service"] = 1 if any(service in url.lower() for service in shortening_services) else 0
        
        # Path extension
        path_parts = parsed_url.path.split('.')
        features["path_extension"] = 1 if len(path_parts) > 1 and len(path_parts[-1]) <= 4 else 0
        
        # Redirection features (placeholder - would need actual HTTP requests)
        features["nb_redirection"] = 0  # Would require following redirects
        features["nb_external_redirection"] = 0  # Would require analysis of redirect chain
        
        # Word analysis
        url_words = re.findall(r'[a-zA-Z]+', url)
        if url_words:
            features["length_words_raw"] = sum(len(word) for word in url_words)
            features["shortest_words_raw"] = min(len(word) for word in url_words)
            features["longest_words_raw"] = max(len(word) for word in url_words)
            features["avg_words_raw"] = features["length_words_raw"] / len(url_words)
        else:
            features["length_words_raw"] = 0
            features["shortest_words_raw"] = 0
            features["longest_words_raw"] = 0
            features["avg_words_raw"] = 0
        
        # Host word analysis
        host_words = re.findall(r'[a-zA-Z]+', hostname)
        if host_words:
            features["shortest_word_host"] = min(len(word) for word in host_words)
            features["longest_word_host"] = max(len(word) for word in host_words)
            features["avg_word_host"] = sum(len(word) for word in host_words) / len(host_words)
        else:
            features["shortest_word_host"] = 0
            features["longest_word_host"] = 0
            features["avg_word_host"] = 0
        
        # Path word analysis
        path_words = re.findall(r'[a-zA-Z]+', parsed_url.path)
        if path_words:
            features["shortest_word_path"] = min(len(word) for word in path_words)
            features["longest_word_path"] = max(len(word) for word in path_words)
            features["avg_word_path"] = sum(len(word) for word in path_words) / len(path_words)
        else:
            features["shortest_word_path"] = 0
            features["longest_word_path"] = 0
            features["avg_word_path"] = 0
        
        # Character repetition
        char_counts = {}
        for char in url:
            char_counts[char] = char_counts.get(char, 0) + 1
        features["char_repeat"] = max(char_counts.values()) if char_counts else 0
        
        # Phishing hints
        phish_keywords = ['secure', 'verify', 'bank', 'support', 'login', 'signin', 'account', 'update', 'confirm']
        features["phish_hints"] = sum(1 for keyword in phish_keywords if keyword in url.lower())
        
        # Brand analysis (placeholder - would need brand database)
        popular_brands = ['google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal', 'ebay']
        features["domain_in_brand"] = 1 if any(brand in domain.lower() for brand in popular_brands) else 0
        features["brand_in_subdomain"] = 1 if any(brand in extracted.subdomain.lower() for brand in popular_brands) else 0
        features["brand_in_path"] = 1 if any(brand in parsed_url.path.lower() for brand in popular_brands) else 0
        
        # Suspicious TLD
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
        features["suspecious_tld"] = 1 if any(tld in url.lower() for tld in suspicious_tlds) else 0
        
        # Statistical report (placeholder)
        features["statistical_report"] = 0  # Would require external reputation database
        
        # HTML/Content features (placeholders - would require fetching page content)
        features["nb_hyperlinks"] = 0
        features["ratio_intHyperlinks"] = 0
        features["ratio_extHyperlinks"] = 0
        features["ratio_nullHyperlinks"] = 0
        features["nb_extCSS"] = 0
        features["ratio_intRedirection"] = 0
        features["ratio_extRedirection"] = 0
        features["ratio_intErrors"] = 0
        features["ratio_extErrors"] = 0
        features["login_form"] = 0
        features["external_favicon"] = 0
        features["links_in_tags"] = 0
        features["submit_email"] = 0
        features["ratio_intMedia"] = 0
        features["ratio_extMedia"] = 0
        features["sfh"] = 0
        features["iframe"] = 0
        features["popup_window"] = 0
        features["safe_anchor"] = 0
        features["onmouseover"] = 0
        features["right_clic"] = 0
        features["empty_title"] = 0
        features["domain_in_title"] = 0
        features["domain_with_copyright"] = 0
        
        # WHOIS and DNS features (placeholders - would require actual queries)
        features["whois_registered_domain"] = 0
        features["domain_registration_length"] = 0
        features["domain_age"] = 0
        features["web_traffic"] = 0
        features["dns_record"] = 0
        features["google_index"] = 0
        features["page_rank"] = 0
        
    except Exception as e:
        # Set default values if parsing fails
        for key in ["length_url", "length_hostname", "ip", "nb_dots", "nb_hyphens", "nb_at", 
                   "nb_qm", "nb_and", "nb_or", "nb_eq", "nb_underscore", "nb_tilde", 
                   "nb_percent", "nb_slash", "nb_star", "nb_colon", "nb_comma", 
                   "nb_semicolumn", "nb_dollar", "nb_space", "nb_www", "nb_com", 
                   "nb_dslash", "http_in_path", "https_token", "ratio_digits_url", 
                   "ratio_digits_host", "punycode", "port", "tld_in_path", 
                   "tld_in_subdomain", "abnormal_subdomain", "nb_subdomains", 
                   "prefix_suffix", "random_domain", "shortening_service", 
                   "path_extension", "nb_redirection", "nb_external_redirection", 
                   "length_words_raw", "char_repeat", "shortest_words_raw", 
                   "shortest_word_host", "shortest_word_path", "longest_words_raw", 
                   "longest_word_host", "longest_word_path", "avg_words_raw", 
                   "avg_word_host", "avg_word_path", "phish_hints", "domain_in_brand", 
                   "brand_in_subdomain", "brand_in_path", "suspecious_tld", 
                   "statistical_report", "nb_hyperlinks", "ratio_intHyperlinks", 
                   "ratio_extHyperlinks", "ratio_nullHyperlinks", "nb_extCSS", 
                   "ratio_intRedirection", "ratio_extRedirection", "ratio_intErrors", 
                   "ratio_extErrors", "login_form", "external_favicon", "links_in_tags", 
                   "submit_email", "ratio_intMedia", "ratio_extMedia", "sfh", "iframe", 
                   "popup_window", "safe_anchor", "onmouseover", "right_clic", 
                   "empty_title", "domain_in_title", "domain_with_copyright", 
                   "whois_registered_domain", "domain_registration_length", 
                   "domain_age", "web_traffic", "dns_record", "google_index", "page_rank"]:
            if key not in features:
                features[key] = 0
    
    return features

def get_explanation(features, prediction):
    """
    Generate detailed explanation for phishing detection based on extracted features
    """
    reasons = []

    if prediction == 1:  # Model predicts Phishing
        # URL length analysis
        if features.get("length_url", 0) > 75:
            reasons.append("The URL is unusually long, a common tactic to obfuscate malicious links.")
        
        # Character analysis
        if features.get("nb_dots", 0) > 3:
            reasons.append("Too many dots in the URL may suggest multiple subdomains to impersonate trusted sites.")
        if features.get("nb_hyphens", 0) > 2:
            reasons.append("Suspicious use of hyphens, often seen in fake domains like 'secure-paypal-login'.")
        if features.get("nb_at", 0) > 0:
            reasons.append("The URL contains '@', which can be used to mask malicious redirections.")
        if features.get("nb_percent", 0) > 3:
            reasons.append("Excessive URL encoding (%) characters may indicate obfuscation attempts.")
        
        # Security indicators
        if features.get("has_https", 1) == 0:
            reasons.append("The URL does not use HTTPS, indicating a lack of encryption.")
        if features.get("ip", 0) == 1 or features.get("domain_in_ip", 0) == 1:
            reasons.append("The domain uses an IP address instead of a name, which is uncommon for trusted sites.")
        
        # Suspicious keywords
        if features.get("phish_hints", 0) > 0 or features.get("suspect_keywords_count", 0) > 0:
            reasons.append("The URL contains suspicious keywords commonly used in phishing attacks (secure, account, update, login, verify, bank, etc.).")
        
        # Domain analysis
        if features.get("prefix_suffix_in_domain", 0) == 1:
            reasons.append("The domain name includes hyphens, which may indicate a fake domain mimicking legitimate sites.")
        if features.get("long_domain", 0) == 1:
            reasons.append("The domain name is unusually long, which may be an attempt to confuse users.")
        if features.get("nb_subdomains", 0) > 2:
            reasons.append("The domain has many subdomains, which could be an attempt to mimic trusted domains.")
        
        # Suspicious TLD
        if features.get("suspecious_tld", 0) == 1:
            reasons.append("The URL uses a suspicious top-level domain often associated with malicious sites.")
        
        # Technical features
        if features.get("double_slash_redirect", 0) == 1:
            reasons.append("The URL has unusual use of double slashes, which may redirect to malicious sites.")
        if features.get("has_port", 0) == 1:
            reasons.append("The URL includes a custom port, which is uncommon in most safe websites.")
        if features.get("nb_sensitive_extension", 0) == 1:
            reasons.append("The URL links to suspicious file types like .exe, .zip, or .scr that could contain malware.")
        
        # Path analysis
        if features.get("length_path", 0) > 50:
            reasons.append("The path part of the URL is excessively long and may hide malicious payloads.")
        if features.get("tld_in_path", 0) == 1:
            reasons.append("The URL path contains domain extensions, which may indicate URL manipulation.")
        
        # Shortening services
        if features.get("shortening_service", 0) == 1:
            reasons.append("The URL uses a link shortening service, which can hide the actual destination.")
        
        # Brand impersonation
        if features.get("brand_in_subdomain", 0) == 1 or features.get("brand_in_path", 0) == 1:
            reasons.append("The URL appears to impersonate a well-known brand in suspicious ways.")
        
        # Character repetition and obfuscation
        if features.get("char_repeat", 0) > 5:
            reasons.append("Excessive character repetition may indicate an attempt to create confusing URLs.")
        if features.get("punycode", 0) == 1:
            reasons.append("The URL uses punycode encoding, which can be used to create deceptive domain names.")
        
        # Digit analysis
        if features.get("ratio_digits_url", 0) > 0.3:
            reasons.append("The URL contains an unusually high proportion of digits, which may indicate generated malicious URLs.")
        
        # Domain age and registration
        if features.get("domain_age", 0) > 0 and features.get("domain_age", 0) < 30:
            reasons.append("The domain is very new (less than 30 days old), which is common for phishing sites.")
        if features.get("domain_registration_length", 0) > 0 and features.get("domain_registration_length", 0) < 365:
            reasons.append("The domain was registered for less than a year, which is suspicious for legitimate businesses.")
        
        if not reasons:
            reasons.append("The model detected patterns consistent with phishing attempts based on multiple URL characteristics.")

    else:  # Model predicts Safe
        positive_indicators = []
        
        if features.get("has_https", 0) == 1:
            positive_indicators.append("Uses secure HTTPS protocol")
        if features.get("nb_subdomains", 0) <= 2:
            positive_indicators.append("Has a reasonable number of subdomains")
        if features.get("phish_hints", 0) == 0:
            positive_indicators.append("Contains no suspicious phishing keywords")
        if features.get("ip", 0) == 0:
            positive_indicators.append("Uses a proper domain name instead of IP address")
        if features.get("length_url", 0) < 75:
            positive_indicators.append("Has a reasonable URL length")
        if features.get("domain_age", 0) > 365:
            positive_indicators.append("Domain is well-established (over 1 year old)")
        
        if positive_indicators:
            reasons.append(f"The URL appears safe based on several positive indicators: {', '.join(positive_indicators)}")
        else:
            reasons.append("The URL appears safe and does not exhibit known phishing patterns.")

    return reasons

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    url = data.get("url", "")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    features = extract_features(url)
    features_df = pd.DataFrame([features])

    prediction = model.predict(features_df)[0]
    result = "Phishing" if prediction == 1 else "Safe"

    explanation = get_explanation(features, prediction)

    return jsonify({"url": url, "prediction": result, "reasons": explanation})

if __name__ == '__main__':
    app.run(debug=True)
