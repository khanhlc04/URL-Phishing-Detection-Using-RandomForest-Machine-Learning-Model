import pandas as pd
import joblib
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier  

# Load dataset
def train_model():
    df = pd.read_csv("Synthetic_Dataset/clean_phishing_dataset.csv")
    
    # Define features and target
    X = df.drop(columns=["url", "label"])
    y = df["label"]
    
    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    # Train Decision Tree model
    model = DecisionTreeClassifier(
    max_depth=10,
    min_samples_split=5,
    min_samples_leaf=3,
    random_state=42
  )

    model.fit(X_train, y_train)

    # Evaluate model
    prediction = model.predict(X_test)
    acc = accuracy_score(y_test, prediction)
    print("Accuracy Score:", acc)

    print(df["label"].value_counts())

    
    # Save model
    joblib.dump(model, "phishing_model_decision_tree.pkl")
    print("✅ Model trained and saved as phishing_model_decision_tree.pkl")

if __name__ == "__main__":
    train_model()
