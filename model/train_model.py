import pandas as pd
import joblib
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier  

def train_model():
    df = pd.read_csv("Synthetic_Dataset/clean_phishing_dataset.csv")
    
    # Define features and target
    X = df.drop(columns=["url", "label"])
    y = df["label"]
    
    feature_names = X.columns.tolist()  # ✅ Lưu lại tên cột
    
    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Train model
    model = DecisionTreeClassifier()
    model.fit(X_train, y_train)

    # Evaluate
    prediction = model.predict(X_test)
    acc = accuracy_score(y_test, prediction)
    print("Accuracy Score:", acc)

    # Save model + feature names
    joblib.dump(model, "phishing_model_decision_tree.pkl")
    joblib.dump(feature_names, "phishing_model_features.pkl")  # ✅ Lưu tên feature

    print("Model and feature names saved successfully.")

if __name__ == "__main__":
    train_model()
