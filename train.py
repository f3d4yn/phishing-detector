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
from config import MODEL_PATH, VECTORIZER_PATH, TEST_SIZE, DATASET_PATH

# ============================================================
# STEP 1 : Load and prepare the URL dataset
# ============================================================
print("Loading URL dataset...")
url_df = pd.read_csv(DATASET_PATH)
print(f"URL dataset shape : {url_df.shape}")
print(f"Label distribution : {url_df['status'].value_counts().to_dict()}")

# ============================================================
# STEP 2 : Load and prepare the Email dataset
# ============================================================
print("\nLoading Email dataset...")
email_df = pd.read_csv("data/email_dataset.csv")
print(f"Email dataset shape : {email_df.shape}")
print(f"Label distribution : {email_df['label'].value_counts().to_dict()}")

# ============================================================
# STEP 3 : Extract features from URL dataset
# ============================================================
print("\nExtracting features from URL dataset...")
url_features_list = []

for index, row in url_df.iterrows():
    try:
        url_input = URLInput(row['url'])
        extractor = FeatureExtractor(url_input)
        features = extractor.extract()
        features['label'] = 1 if row['status'] == 'phishing' else 0
        url_features_list.append(features)

        if index % 1000 == 0:
            print(f"  Processed {index} / {len(url_df)} URLs...")

    except Exception as e:
        continue

print(f"URL features extracted : {len(url_features_list)}")

# ============================================================
# STEP 4 : Extract features from Email dataset
# ============================================================
print("\nExtracting features from Email dataset...")
email_features_list = []

for index, row in email_df.iterrows():
    try:
        # Create a fake sender so EmailInput is valid
        email_input = EmailInput(
            raw_text=str(row['text_combined']),
            subject="",
            sender="sender@domain.com"
        )
        extractor = FeatureExtractor(email_input)
        features = extractor.extract()
        features['label'] = int(row['label'])
        email_features_list.append(features)

        if index % 1000 == 0:
            print(f"  Processed {index} / {len(email_df)} emails...")

    except Exception as e:
        continue

print(f"Email features extracted : {len(email_features_list)}")

# ============================================================
# STEP 5 : Combine both datasets
# ============================================================
print("\nCombining datasets...")

url_features_df = pd.DataFrame(url_features_list)
email_features_df = pd.DataFrame(email_features_list)

# Combine URL and email features into one DataFrame
combined_df = pd.concat([url_features_df, email_features_df], ignore_index=True)

# Fill any missing values with 0
combined_df = combined_df.fillna(0)

print(f"Combined dataset shape : {combined_df.shape}")
print(f"Label distribution : {combined_df['label'].value_counts().to_dict()}")

# ============================================================
# STEP 6 : Prepare X and y
# ============================================================
print("\nPreparing data...")

X = combined_df.drop(columns=['label'])
y = combined_df['label']

# ============================================================
# STEP 7 : Split into train and test sets
# ============================================================
print("\nSplitting dataset...")

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=TEST_SIZE,
    random_state=42,
    stratify=y
)

print(f"Training set : {X_train.shape[0]} samples")
print(f"Testing set  : {X_test.shape[0]} samples")

# ============================================================
# STEP 8 : Train the model
# ============================================================
print("\nTraining the model...")

model = MLModel()
model.train(X_train, y_train)

# ============================================================
# STEP 9 : Evaluate the model
# ============================================================
print("\nEvaluating the model...")

evaluator = Evaluator(model)
evaluator.evaluate(X_test, y_test)
evaluator.print_report()
evaluator.confusion_matrix(X_test, y_test)

# ============================================================
# STEP 10 : Save the model
# ============================================================
print("\nSaving the model...")

os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
model.save(MODEL_PATH, VECTORIZER_PATH)

print("\nRetraining complete! You can now run main.py to analyze URLs and Emails.")
