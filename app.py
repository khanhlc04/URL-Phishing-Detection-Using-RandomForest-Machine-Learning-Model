from flask import Flask, request, jsonify, render_template
import pandas as pd
import joblib
import re
import socket
from urllib.parse import urlparse
import tldextract

app = Flask(__name__)

# Load trained model và scaler
model = joblib.load("model/phishing_model_randoom_forest.pkl")
scaler = joblib.load("model/phishing_model_scaler.pkl")

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
        features["length_url"] = len(url)
        features["length_hostname"] = len(parsed_url.netloc) if parsed_url.netloc else 0
        hostname = parsed_url.netloc.split(':')[0]  # Remove port if present
        try:
            socket.inet_aton(hostname)
            features["ip"] = 1
        except socket.error:
            features["ip"] = 0
        features["nb_dots"] = url.count('.')
        features["nb_hyphens"] = url.count('-')
        features["nb_at"] = url.count('@')
        features["nb_qm"] = url.count('?')
        features["nb_and"] = url.count('&')
        features["nb_eq"] = url.count('=')
        features["nb_underscore"] = url.count('_')
        features["nb_percent"] = url.count('%')
        features["nb_slash"] = url.count('/')
        features["nb_www"] = url.lower().count('www')
        features["nb_com"] = url.lower().count('com')
        features["http_in_path"] = 1 if 'http' in parsed_url.path.lower() else 0
        features["https_token"] = 1 if url.lower().startswith('https') else 0
        features["punycode"] = 1 if 'xn--' in url.lower() else 0
        port_match = re.search(r':(\d+)', parsed_url.netloc)
        features["port"] = 1 if port_match and port_match.group(1) not in ['80', '443'] else 0
        subdomains = extracted.subdomain.split('.') if extracted.subdomain else []
        features["nb_subdomains"] = len([s for s in subdomains if s])
    except Exception as e:
        for key in [
            "length_url", "length_hostname", "ip", "nb_dots", "nb_hyphens", "nb_at", "nb_qm", "nb_and", "nb_eq", "nb_underscore", "nb_percent", "nb_slash", "nb_www", "nb_com", "http_in_path", "https_token", "punycode", "port", "nb_subdomains"
        ]:
            if key not in features:
                features[key] = 0
    return features

def get_explanation(features, prediction):
    """
    Generate detailed explanation for phishing detection based on extracted features
    """
    reasons = []

    if prediction == 1:
        if features.get("length_url", 0) > 75:
            reasons.append("URL quá dài, đây là một thủ thuật thường gặp để che giấu liên kết độc hại.")
        if features.get("length_hostname", 0) > 30:
            reasons.append("Tên máy chủ (hostname) quá dài, có thể nhằm mục đích gây khó hiểu hoặc che giấu.")
        if features.get("ip", 0) == 1:
            reasons.append("Tên miền sử dụng địa chỉ IP thay vì tên miền, điều này hiếm gặp ở các trang web uy tín.")
        if features.get("nb_dots", 0) > 3:
            reasons.append("Có quá nhiều dấu chấm trong URL, có thể là dấu hiệu của nhiều tên miền phụ giả mạo.")
        if features.get("nb_hyphens", 0) > 2:
            reasons.append("Có nhiều dấu gạch ngang, thường xuất hiện ở các tên miền giả mạo.")
        if features.get("nb_at", 0) > 0:
            reasons.append("URL chứa ký tự '@', có thể dùng để che giấu chuyển hướng độc hại.")
        if features.get("nb_qm", 0) > 0:
            reasons.append("URL chứa dấu '?', có thể là dấu hiệu thao túng truy vấn.")
        if features.get("nb_and", 0) > 2:
            reasons.append("Có quá nhiều dấu '&', có thể là truy vấn phức tạp hoặc bị che giấu.")
        if features.get("nb_eq", 0) > 2:
            reasons.append("Có quá nhiều dấu '=', có thể là dấu hiệu sử dụng tham số đáng ngờ.")
        if features.get("nb_underscore", 0) > 2:
            reasons.append("Có nhiều dấu gạch dưới trong URL, có thể là dấu hiệu bất thường.")
        if features.get("nb_percent", 0) > 3:
            reasons.append("Có quá nhiều ký tự mã hóa (%) trong URL, có thể là dấu hiệu che giấu thông tin.")
        if features.get("nb_slash", 0) > 5:
            reasons.append("Có quá nhiều dấu gạch chéo '/', có thể là dấu hiệu chuyển hướng hoặc che giấu.")
        if features.get("nb_www", 0) > 1:
            reasons.append("Xuất hiện nhiều 'www', có thể là tên miền phụ đáng ngờ.")
        if features.get("nb_com", 0) > 2:
            reasons.append("Xuất hiện nhiều 'com', có thể là dấu hiệu sử dụng tên miền đáng ngờ.")
        if features.get("http_in_path", 0) == 1:
            reasons.append("Đường dẫn chứa 'http', có thể là dấu hiệu chuyển hướng hoặc lừa đảo.")
        if features.get("https_token", 0) == 0:
            reasons.append("URL không sử dụng giao thức HTTPS, thiếu mã hóa bảo mật.")
        if features.get("punycode", 0) == 1:
            reasons.append("URL sử dụng mã hóa punycode, có thể dùng để tạo tên miền giả mạo.")
        if features.get("port", 0) == 1:
            reasons.append("URL sử dụng cổng (port) tùy chỉnh, điều này không phổ biến ở các website an toàn.")
        if features.get("nb_subdomains", 0) > 2:
            reasons.append("Tên miền có quá nhiều subdomain, có thể là dấu hiệu giả mạo tên miền uy tín.")
        if not reasons:
            reasons.append("Mô hình phát hiện các dấu hiệu lừa đảo dựa trên nhiều đặc điểm của URL.")
    else:
        positive_indicators = []
        if features.get("https_token", 0) == 1:
            positive_indicators.append("Sử dụng giao thức HTTPS bảo mật")
        if features.get("nb_subdomains", 0) <= 2:
            positive_indicators.append("Số lượng subdomain hợp lý")
        if features.get("ip", 0) == 0:
            positive_indicators.append("Sử dụng tên miền thay vì địa chỉ IP")
        if features.get("length_url", 0) < 75:
            positive_indicators.append("Độ dài URL hợp lý")
        if features.get("length_hostname", 0) < 30:
            positive_indicators.append("Độ dài hostname hợp lý")
        if features.get("punycode", 0) == 0:
            positive_indicators.append("Không sử dụng mã hóa punycode")
        if features.get("port", 0) == 0:
            positive_indicators.append("Không sử dụng cổng (port) tùy chỉnh")
        if positive_indicators:
            reasons.append(f"URL có các dấu hiệu an toàn: {', '.join(positive_indicators)}")
        else:
            reasons.append("URL có vẻ an toàn và không có dấu hiệu lừa đảo rõ rệt.")
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
    # Chuẩn hóa dữ liệu đầu vào
    features_scaled = scaler.transform(features_df)
    prediction = model.predict(features_scaled)[0]
    result = "Phishing" if prediction == 1 else "Safe"
    explanation = get_explanation(features, prediction)
    return jsonify({"url": url, "prediction": result, "reasons": explanation})

if __name__ == '__main__':
    app.run(debug=True)
