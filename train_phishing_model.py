import os
import argparse
import json
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score

from phishing_forensics import extract_url_features

def detect_columns(df):
    """
    Automatically detects the URL column and Label/Result column in the dataframe.
    Returns: (url_column_name, label_column_name)
    """
    columns = list(df.columns)
    
    # 1. URL Column detection
    url_col = None
    # Look for exact match (case-insensitive)
    url_keywords = ["url", "urls", "url_address", "address", "link", "links", "text", "raw_url"]
    for col in columns:
        if col.lower() in url_keywords:
            url_col = col
            break
            
    if not url_col:
        # Look for partial matches
        for col in columns:
            if "url" in col.lower() or "link" in col.lower():
                url_col = col
                break
                
    if not url_col:
        # Fallback to first column
        url_col = columns[0]
        
    # 2. Label/Result Column detection
    label_col = None
    label_keywords = ["label", "labels", "result", "results", "status", "target", "class", "phishing"]
    for col in columns:
        if col.lower() in label_keywords:
            label_col = col
            break
            
    if not label_col:
        # Look for partial matches
        for col in columns:
            if any(k in col.lower() for k in ["label", "result", "status", "target", "class", "phish"]):
                label_col = col
                break
                
    if not label_col:
        # Fallback to last column
        label_col = columns[-1]
        
    return url_col, label_col

def clean_and_map_labels(df, label_col):
    """
    Maps various label definitions (e.g. status, strings) to binary 0/1.
    0 = Legitimate/Benign, 1 = Phishing/Scam
    """
    labels = df[label_col].astype(str).str.lower().str.strip()
    
    binary_labels = []
    for val in labels:
        if val in ["0", "0.0", "legitimate", "benign", "safe", "ok", "good"]:
            binary_labels.append(0)
        elif val in ["1", "1.0", "phishing", "dangerous", "bad", "scam", "phish"]:
            binary_labels.append(1)
        else:
            # Fallback for unknown text: if it looks like benign/safe
            if "legit" in val or "benign" in val or "safe" in val:
                binary_labels.append(0)
            else:
                binary_labels.append(1) # default to suspect
                
    return np.array(binary_labels)

def train_and_evaluate(dataset_path, output_dir="models", progress_callback=None):
    """
    Programmatic entry point for training and evaluation.
    Can be used by Streamlit UI with a progress_callback.
    """
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"Loading dataset: {dataset_path} ...")
    if dataset_path.endswith(".parquet"):
        df = pd.read_parquet(dataset_path)
    else:
        df = pd.read_csv(dataset_path)
        
    print(f"Dataset Shape: {df.shape}")
    
    # Detect columns
    url_col, label_col = detect_columns(df)
    print(f"Auto-detected columns: URL = '{url_col}' | Label = '{label_col}'")
    
    # Filter nulls/empty URLs
    initial_len = len(df)
    df = df.dropna(subset=[url_col])
    df = df[df[url_col].astype(str).str.strip() != ""]
    valid_len = len(df)
    
    null_dropped = initial_len - valid_len
    print(f"Data Quality: Dropped {null_dropped} null/empty rows. {valid_len} valid URLs remaining.")
    
    # Map target label
    y = clean_and_map_labels(df, label_col)
    urls = df[url_col].tolist()
    
    # Get statistics
    benign_count = int(np.sum(y == 0))
    phishing_count = int(np.sum(y == 1))
    total_valid = len(y)
    
    stats = {
        "total_records": total_valid,
        "benign_count": benign_count,
        "phishing_count": phishing_count,
        "benign_percentage": float(benign_count / total_valid * 100) if total_valid > 0 else 0,
        "phishing_percentage": float(phishing_count / total_valid * 100) if total_valid > 0 else 0
    }
    
    print(f"Dataset Statistics:")
    print(f"  Benign: {benign_count} ({stats['benign_percentage']:.2f}%)")
    print(f"  Phishing: {phishing_count} ({stats['phishing_percentage']:.2f}%)")
    
    # Extract features
    print("Extracting features from URLs...")
    X_list = []
    for idx, url in enumerate(urls):
        X_list.append(extract_url_features(url))
        if progress_callback:
            # Let Streamlit callback render progress
            progress_callback(idx + 1, total_valid)
        elif (idx + 1) % 1000 == 0 or (idx + 1) == total_valid:
            print(f"  Processed {idx + 1}/{total_valid} URLs...")
            
    X = np.array(X_list)
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    print(f"Split completed: Train={len(y_train)} | Test={len(y_test)}")
    
    # Train Models
    print("Training RandomForestClassifier...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    
    print("Training LogisticRegression...")
    lr = LogisticRegression(max_iter=1000, random_state=42)
    lr.fit(X_train, y_train)
    
    # Evaluate RF
    y_pred_rf = rf.predict(X_test)
    y_prob_rf = rf.predict_proba(X_test)[:, 1]
    
    metrics_rf = {
        "accuracy": float(accuracy_score(y_test, y_pred_rf)),
        "precision": float(precision_score(y_test, y_pred_rf, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred_rf, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred_rf, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, y_prob_rf))
    }
    
    # Evaluate LR
    y_pred_lr = lr.predict(X_test)
    y_prob_lr = lr.predict_proba(X_test)[:, 1]
    
    metrics_lr = {
        "accuracy": float(accuracy_score(y_test, y_pred_lr)),
        "precision": float(precision_score(y_test, y_pred_lr, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred_lr, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred_lr, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, y_prob_lr))
    }
    
    print("\nEvaluation Summary:")
    print(f"Random Forest - F1: {metrics_rf['f1']:.4f} | Accuracy: {metrics_rf['accuracy']:.4f}")
    print(f"Logistic Regression - F1: {metrics_lr['f1']:.4f} | Accuracy: {metrics_lr['accuracy']:.4f}")
    
    # Choose best model (comparing F1 score)
    if metrics_rf['f1'] >= metrics_lr['f1']:
        best_model = rf
        best_model_name = "Random Forest Classifier"
        best_metrics = metrics_rf
    else:
        best_model = lr
        best_model_name = "Logistic Regression"
        best_metrics = metrics_lr
        
    print(f"\nBest Model Selected: {best_model_name}")
    
    # Save best model
    model_path = os.path.join(output_dir, "phishing_model.joblib")
    joblib.dump(best_model, model_path)
    print(f"Saved best model to: {model_path}")
    
    # Save metrics
    metrics_report = {
        "best_model_name": best_model_name,
        "dataset_statistics": stats,
        "models": {
            "Random Forest Classifier": metrics_rf,
            "Logistic Regression": metrics_lr
        }
    }
    
    metrics_path = os.path.join(output_dir, "phishing_metrics.json")
    with open(metrics_path, "w") as f:
        json.dump(metrics_report, f, indent=4)
    print(f"Saved training metrics to: {metrics_path}")
    
    return metrics_report

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Repeatable Phishing URL Model Training Pipeline")
    parser.add_argument("--dataset", "-d", type=str, default="datasets/Training.parquet",
                        help="Path to the dataset (CSV or Parquet file)")
    parser.add_argument("--output_dir", "-o", type=str, default="models",
                        help="Directory to save the trained model and metrics")
                        
    args = parser.parse_args()
    
    if not os.path.exists(args.dataset):
        print(f"ERROR: Dataset path does not exist: {args.dataset}")
        exit(1)
        
    train_and_evaluate(args.dataset, args.output_dir)
