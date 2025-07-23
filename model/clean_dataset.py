import pandas as pd
import re
import socket
import urllib.parse
from urllib.parse import urlparse
import requests
import whois
from datetime import datetime
import dns.resolver
import tldextract

# Hàm trích xuất đặc trưng
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

# Bước 1: Đọc dữ liệu ban đầu từ file CSV "phishing_dataset.csv"
df = pd.read_csv("Synthetic_Dataset/phishing_dataset.csv")  

# Bước 2: Trích xuất các đặc trưng từ cột URL
# Với mỗi URL trong cột 'url', gọi hàm extract_features để tạo ra các chỉ số đặc trưng
# apply(pd.Series) để chuyển dict kết quả thành các cột riêng biệt trong DataFrame
features_df = df['url'].apply(extract_features).apply(pd.Series)

# Bước 3: Gộp các đặc trưng mới vào dataframe ban đầu
# Kết hợp cột 'url', các đặc trưng trích xuất và cột 'label' (nhãn)
final_df = pd.concat([df[['url']], features_df, df[['label']]], axis=1)

# Bước 4: Lưu dữ liệu đã được bổ sung đặc trưng thành file CSV mới "phishing_dataset.csv"
final_df.to_csv("Synthetic_Dataset/clean_phishing_dataset.csv", index=False)
print("Đã tạo file clean_phishing_dataset.csv")