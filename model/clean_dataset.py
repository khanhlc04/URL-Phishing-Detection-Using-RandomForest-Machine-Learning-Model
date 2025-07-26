import pandas as pd
import numpy as np

input_path = "Synthetic_Dataset/phishing_dataset_dirty.csv"
output_path = "Synthetic_Dataset/clean_phishing_dataset.csv"

df = pd.read_csv(input_path)

# 1. Loại bỏ dòng trùng lặp
df = df.drop_duplicates()

df.to_csv(output_path, index=False)
# Drop các dòng có dữ liệu trùng lặp
# ...existing code...

# Ép kiểu toàn bộ các cột (trừ url) về số
for col in df.columns:
    if col not in ['url']:
        df[col] = pd.to_numeric(df[col], errors='coerce')

def is_row_dirty(row):
    binary_cols = [
        'ip', 'http_in_path', 'https_token', 'punycode', 'port'
    ]
    for col in row.index:
        if col in ['url']:
            continue
        val = row[col]
        if pd.isnull(val):
            return True
        # Nếu là cột chỉ nhận 0/1
        if col in binary_cols:
            if val not in [0, 1]:
                return True
        else:
            # Chỉ nhận số nguyên
            if not (isinstance(val, (int, float)) and float(val).is_integer()):
                return True
    return False
df_clean = df[~df.apply(is_row_dirty, axis=1)].dropna()

df_clean.to_csv(output_path, index=False)
print(f"Đã lưu dữ liệu sạch tại: {output_path}")
