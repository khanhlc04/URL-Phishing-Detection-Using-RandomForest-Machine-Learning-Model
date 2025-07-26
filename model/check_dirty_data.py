import pandas as pd
import numpy as np

input_path = "Synthetic_Dataset/clean_phishing_dataset.csv"
df = pd.read_csv(input_path)

# Thống kê nhãn
if 'label' in df.columns:
    print("Thống kê nhãn:")
    print(df['label'].value_counts())
    print(f"Tỉ lệ nhãn 0: {((df['label']==0).sum()/len(df)):.2f}, nhãn 1: {((df['label']==1).sum()/len(df)):.2f}")

# Ép kiểu các cột về float (trừ url)
for col in df.columns:
    if col not in ['url']:
        df[col] = pd.to_numeric(df[col], errors='coerce')

# 1. Đếm số dòng bị trùng lặp
duplicate_rows = df.duplicated().sum()
print(f"Số dòng bị trùng lặp: {duplicate_rows}")

# 2. Kiểm tra từng cột
for col in df.columns:
    if col in ['url', 'label']:
        continue
    col_data = df[col]
    num_nan = col_data.isnull().sum()
    num_str = col_data.apply(lambda x: isinstance(x, str)).sum()
    # Số ô không phải số nguyên (loại trừ NaN)
    num_not_int = col_data.apply(lambda x: not (pd.isnull(x) or (isinstance(x, (int, float)) and float(x).is_integer()))).sum()

    # Nếu là cột chỉ nhận 0/1 thì kiểm tra thêm
    binary_cols = [
        'ip', 'http_in_path', 'https_token', 'punycode', 'port'
    ]
    if col in binary_cols:
        num_not_binary = col_data.apply(lambda x: not (pd.isnull(x) or x in [0, 1])).sum()
        print(f"Cột {col}: {num_nan} ô trống, {num_not_binary} ô không phải 0/1")
    else:
        print(f"Cột {col}: {num_nan} ô trống, {num_not_int} ô không phải số nguyên")
