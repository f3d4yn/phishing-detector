# numpy for numerical calculations
import numpy as np

# metrics from sklearn to evaluate the model performance
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score
)

# MLModel is what we are evaluating
from src.model.ml_model import MLModel

class Evaluator:

    def __init__(self, model: MLModel):
        # Store the trained model we want to evaluate
        self.model = model
        
        # This dictionary will store all computed metrics
        self.metrics = {}

    def evaluate(self, X, y_true) -> dict:
        # X is the test features
        # y_true is the real labels (0 or 1) from the dataset
        
        # Step 1 : get the phishing probability for each sample
        probabilities = [self.model.predict(X.iloc[[i]]) for i in range(len(X))]
        
        # Step 2 : convert probabilities to binary predictions
        # If probability > 0.5 -> phishing (1), otherwise legitimate (0)
        y_pred = [1 if p > 0.5 else 0 for p in probabilities]
        
        # Step 3 : calculate all metrics
        
        # Accuracy : percentage of correct predictions overall
        self.metrics['accuracy'] = accuracy_score(y_true, y_pred)
        
        # Precision : of all emails flagged as phishing, how many were really phishing?
        self.metrics['precision'] = precision_score(y_true, y_pred)
        
        # Recall : of all real phishing emails, how many did we catch?
        self.metrics['recall'] = recall_score(y_true, y_pred)
        
        # F1 Score : balance between precision and recall (most important metric)
        self.metrics['f1_score'] = f1_score(y_true, y_pred)
        
        # ROC AUC : measures how well the model separates the two classes
        self.metrics['roc_auc'] = roc_auc_score(y_true, probabilities)
        
        return self.metrics

    def confusion_matrix(self, X, y_true):
        # Get predictions
        probabilities = [self.model.predict(X.iloc[[i]]) for i in range(len(X))]
        y_pred = [1 if p > 0.5 else 0 for p in probabilities]
        
        # Confusion matrix shows:
        # True Negatives  | False Positives
        # False Negatives | True Positives
        cm = confusion_matrix(y_true, y_pred)
        
        print("Confusion Matrix:")
        print(f"True Negatives  (legitimate correctly identified) : {cm[0][0]}")
        print(f"False Positives (legitimate wrongly flagged)      : {cm[0][1]}")
        print(f"False Negatives (phishing missed)                 : {cm[1][0]}")
        print(f"True Positives  (phishing correctly caught)       : {cm[1][1]}")
        
        return cm

    def print_report(self):
        # Print all metrics in a readable format
        if not self.metrics:
            print("No metrics yet. Call evaluate() first.")
            return
        
        print("=" * 40)
        print("       MODEL EVALUATION REPORT")
        print("=" * 40)
        print(f"Accuracy  : {self.metrics['accuracy']:.2%}")
        print(f"Precision : {self.metrics['precision']:.2%}")
        print(f"Recall    : {self.metrics['recall']:.2%}")
        print(f"F1 Score  : {self.metrics['f1_score']:.2%}")
        print(f"ROC AUC   : {self.metrics['roc_auc']:.2%}")
        print("=" * 40)