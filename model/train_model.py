import pandas as pd
import joblib
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier  
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.preprocessing import StandardScaler

def train_model():
    df = pd.read_csv("Synthetic_Dataset/clean_phishing_dataset.csv")
    
    # Define features and target
    X = df.drop(columns=["url", "label"])
    y = df["label"]
    
    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # Chuẩn hóa dữ liệu nhưng giữ lại DataFrame để bảo toàn tên cột
    scaler = StandardScaler()
    X_train_scaled = pd.DataFrame(scaler.fit_transform(X_train), columns=X_train.columns, index=X_train.index)
    X_test_scaled = pd.DataFrame(scaler.transform(X_test), columns=X_test.columns, index=X_test.index)

    # Train model
    # model = DecisionTreeClassifier()
    model = RandomForestClassifier()
    # model = GaussianNB()
    model.fit(X_train_scaled, y_train)

    # Evaluate
    prediction = model.predict(X_test_scaled)
    acc = accuracy_score(y_test, prediction)
    print("Accuracy Score:", acc)

    # Save model và scaler
    joblib.dump(model, "phishing_model_randoom_forest.pkl")
    joblib.dump(scaler, "phishing_model_scaler.pkl")
    print("Model và scaler đã được lưu.")

    # Kiểm tra nhanh tỷ lệ nhãn

if __name__ == "__main__":
    train_model()
