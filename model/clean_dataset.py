import pandas as pd

# Hàm trích xuất đặc trưng
def extract_features(url):
    features = {
        "length_url": len(url),
        "nb_dots": url.count('.'),
        "nb_hyphens": url.count('-'),
        "nb_slash": url.count('/'),
        "nb_qm": url.count('?'),
        "nb_eq": url.count('='),
        "nb_at": url.count('@'),
        "nb_digits": sum(c.isdigit() for c in url),
        "has_https": 1 if url.startswith("https") else 0,
        "suspect_words": 1 if any(word in url for word in ["secure", "verify", "bank", "support"]) else 0
    }
    return features

# Bước 1: Đọc dữ liệu ban đầu từ file CSV "url_dataset.csv"
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