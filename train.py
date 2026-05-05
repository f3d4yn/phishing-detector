import sys
import os
import pandas as pd
import numpy as np

sys.path.append(os.path.abspath('.'))

from src.features.feature_extractor import FeatureExtractor
from src.inputs.url_input import URLInput
from src.inputs.email_input import EmailInput
from src.model.ml_model import MLModel
from src.model.evaluator import Evaluator
from sklearn.model_selection import train_test_split
from config import (
    URL_MODEL_PATH, URL_VECTORIZER_PATH,
    EMAIL_MODEL_PATH, EMAIL_VECTORIZER_PATH,
    MODELS_DIR,
    TEST_SIZE
)

# ============================================================
#   LOADING CONSOLIDATED DATASETS
# ============================================================
print("=" * 60)
print("  LOADING CONSOLIDATED DATASETS")
print("=" * 60)

print("\n[1/2] Loading consolidated URL dataset...")
all_urls = pd.read_csv("data/all_urls.csv").dropna()
print(f"      {len(all_urls)} samples | {all_urls['label'].value_counts().to_dict()}")

print("\n[2/2] Loading consolidated Email dataset...")
all_emails = pd.read_csv("data/all_emails.csv").dropna()
print(f"      {len(all_emails)} samples | {all_emails['label'].value_counts().to_dict()}")

# ============================================================
#   EXTRACTING URL FEATURES
# ============================================================
print("\n" + "=" * 60)
print("  EXTRACTING URL FEATURES")
print("=" * 60)

url_features_list = []
for index, row in all_urls.iterrows():
    try:
        url_input = URLInput(str(row['url']))
        extractor = FeatureExtractor(url_input)
        features  = extractor.extract()
        features['label'] = int(row['label'])
        url_features_list.append(features)
        if index % 10000 == 0:
            print(f"  Processed {index} / {len(all_urls)} URLs...")
    except Exception:
        continue

print(f"URL features extracted : {len(url_features_list)}")

# ============================================================
#   EXTRACTING EMAIL FEATURES
# ============================================================
print("\n" + "=" * 60)
print("  EXTRACTING EMAIL FEATURES")
print("=" * 60)

email_features_list = []
for index, row in all_emails.iterrows():
    try:
        email_input = EmailInput(
            raw_text=str(row['text']),
            subject="",
            sender="sender@domain.com"
        )
        extractor = FeatureExtractor(email_input)
        features  = extractor.extract()
        features['label'] = int(row['label'])
        email_features_list.append(features)
        if index % 10000 == 0:
            print(f"  Processed {index} / {len(all_emails)} emails...")
    except Exception:
        continue

print(f"Email features extracted : {len(email_features_list)}")

# ============================================================
#   PREPARING DATA — SÉPARÉ PAR TYPE
# ============================================================
print("\n" + "=" * 60)
print("  PREPARING DATA")
print("=" * 60)

url_df   = pd.DataFrame(url_features_list).fillna(0)
email_df = pd.DataFrame(email_features_list).fillna(0)

print(f"\nURL dataset shape   : {url_df.shape}")
print(f"Email dataset shape : {email_df.shape}")

X_url   = url_df.drop(columns=['label'])
y_url   = url_df['label']

X_email = email_df.drop(columns=['label'])
y_email = email_df['label']

# ============================================================
#   SPLITTING
# ============================================================
print("\n" + "=" * 60)
print("  SPLITTING DATASETS")
print("=" * 60)

X_url_train, X_url_test, y_url_train, y_url_test = train_test_split(
    X_url, y_url, test_size=TEST_SIZE, random_state=42, stratify=y_url
)

X_email_train, X_email_test, y_email_train, y_email_test = train_test_split(
    X_email, y_email, test_size=TEST_SIZE, random_state=42, stratify=y_email
)

# ============================================================
#   TRAINING — MODÈLE URL
# ============================================================
print("\n" + "=" * 60)
print("  TRAINING URL MODEL")
print("=" * 60)

url_model = MLModel()
url_model.train(X_url_train, y_url_train)

print("\n--- URL Model Evaluation ---")
url_evaluator = Evaluator(url_model)
url_evaluator.evaluate(X_url_test, y_url_test)
url_evaluator.print_report()

# ============================================================
#   TRAINING — MODÈLE EMAIL
# ============================================================
print("\n" + "=" * 60)
print("  TRAINING EMAIL MODEL")
print("=" * 60)

email_model = MLModel()
email_model.train(X_email_train, y_email_train)

print("\n--- Email Model Evaluation ---")
email_evaluator = Evaluator(email_model)
email_evaluator.evaluate(X_email_test, y_email_test)
email_evaluator.print_report()

# ============================================================
#   SAVING 
# ============================================================
os.makedirs(MODELS_DIR, exist_ok=True)

# URL model
url_model.save(URL_MODEL_PATH, URL_VECTORIZER_PATH)

# Email model
email_model.save(EMAIL_MODEL_PATH, EMAIL_VECTORIZER_PATH)

print("\nRetraining complete with 2 separate models!")