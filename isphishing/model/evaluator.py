import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score
)
from isphishing.model.ml_model import MLModel

class Evaluator:

    def __init__(self, model: MLModel):
        self.model = model
        self.metrics = {}

    def _get_predictions(self, X):
        """Helper to get probabilities and binary predictions in batch."""
        
        
        probabilities = self.model.predict_proba(X)[:, 1]
        y_pred = (probabilities > 0.5).astype(int)
        return probabilities, y_pred

    def evaluate(self, X, y_true) -> dict:
        probabilities, y_pred = self._get_predictions(X)

        self.metrics['accuracy']  = accuracy_score(y_true, y_pred)
        self.metrics['precision'] = precision_score(y_true, y_pred)
        self.metrics['recall']    = recall_score(y_true, y_pred)
        self.metrics['f1_score']  = f1_score(y_true, y_pred)
        self.metrics['roc_auc']   = roc_auc_score(y_true, probabilities)

        return self.metrics

    def confusion_matrix(self, X, y_true):
        _, y_pred = self._get_predictions(X)

        cm = confusion_matrix(y_true, y_pred)
        print("Confusion Matrix:")
        print(f"True Negatives  (legitimate correctly identified) : {cm[0][0]}")
        print(f"False Positives (legitimate wrongly flagged)      : {cm[0][1]}")
        print(f"False Negatives (phishing missed)                 : {cm[1][0]}")
        print(f"True Positives  (phishing correctly caught)       : {cm[1][1]}")
        return cm

    def print_report(self):
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