import pandas as pd
import numpy as np
import random

# Đọc dữ liệu
df = pd.read_csv("Synthetic_Dataset/phising_dataset.csv")

# Chọn 5% dòng để làm bẩn
num_dirty = int(0.05 * len(df))
dirty_idxs = random.sample(range(len(df)), num_dirty)
df_dirty = df.copy()

for idx in dirty_idxs:
    # Chọn ngẫu nhiên 1-2 cột để làm bẩn (trừ url, label)
    cols = [c for c in df.columns if c not in ['url', 'label']]
    dirty_cols = random.sample(cols, k=random.randint(1,2))
    for col in dirty_cols:
        # Chọn kiểu bẩn: chuỗi, float, hoặc NaN
        r = random.random()
        if r < 0.33:
            # Gán chuỗi
            df_dirty.at[idx, col] = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=5))
        elif r < 0.66:
            # Gán NaN
            df_dirty.at[idx, col] = np.nan
        else:
            df_dirty.at[idx, col] = random.uniform(0, 1)
# Thêm các dòng bẩn vào lại để tạo trùng lặp
df_dirty = pd.concat([df_dirty, df_dirty.iloc[dirty_idxs]], ignore_index=True)

# Lưu file dữ liệu bẩn
df_dirty.to_csv("Synthetic_Dataset/phishing_dataset_dirty.csv", index=False)
print(f"Đã tạo dữ liệu bẩn tại: Synthetic_Dataset/phishing_dataset_dirty.csv")
