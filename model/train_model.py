import pandas as pd
import joblib
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier  
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB

def train_model():
    df = pd.read_csv("Synthetic_Dataset/clean_phishing_dataset.csv")
    
    # Define features and target
    X = df.drop(columns=["url", "label"])
    y = df["label"]
    
    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Train model
    # model = DecisionTreeClassifier()
    # model = RandomForestClassifier()
    model = GaussianNB()
    model.fit(X_train, y_train)

    # Evaluate
    prediction = model.predict(X_test)
    acc = accuracy_score(y_test, prediction)
    print("Accuracy Score:", acc)

    # Save model + feature names
    # joblib.dump(model, "phishing_model_decision_tree.pkl")
    # joblib.dump(model, "phishing_model_randoom_forest.pkl")
    joblib.dump(model, "phishing_model_naive_bayes.pkl")

    print("Model and feature names saved successfully.")

if __name__ == "__main__":
    train_model()
