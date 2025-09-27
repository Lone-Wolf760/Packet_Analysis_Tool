import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

def train_model(X, y):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    preds = model.predict(X_test)
    print("📊 Model Performance:")
    print(classification_report(y_test, preds))
    return model

def predict_live(model, df):
    X_live = df.copy()
    X_live["protocol"] = X_live["protocol"].astype('category').cat.codes
    X_live["flags"] = X_live["flags"].fillna("None").astype('category').cat.codes
    df["predicted_label"] = model.predict(X_live)
    return df

def save_model(model, filename="ml_model.pkl"):
    joblib.dump(model, filename)

def load_model(filename="ml_model.pkl"):
    return joblib.load(filename)
