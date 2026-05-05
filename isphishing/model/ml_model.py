import joblib
import numpy as np
import pandas as pd
from xgboost import XGBClassifier
from xgboost.callback import EarlyStopping
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split

class MLModel:

    def __init__(self):
        self.model = XGBClassifier(
            n_estimators=2000,
            max_depth=6,
            learning_rate=0.02,
            subsample=0.8,
            colsample_bytree=0.8,
            min_child_weight=3,
            gamma=0.1,
            reg_alpha=0.1,
            reg_lambda=1.5,
            eval_metric='logloss',
            random_state=42,
            n_jobs=-1,
            callbacks=[EarlyStopping(rounds=50)]
        )

        self.vectorizer = TfidfVectorizer(
            max_features=1000,
            ngram_range=(1, 2),
            sublinear_tf=True
        )
        self.is_trained = False
        self.accuracy = 0.0

    def _prepare(self, X: pd.DataFrame, fit: bool = False) -> pd.DataFrame:
        if fit:
            text_vectors = self.vectorizer.fit_transform(X['cleaned_text'])
        else:
            text_vectors = self.vectorizer.transform(X['cleaned_text'])

        text_df = pd.DataFrame(
            text_vectors.toarray(),
            columns=[f"word_{i}" for i in range(text_vectors.shape[1])],
            index=X.index
        )
        X_numeric = X.drop(columns=['cleaned_text']).reset_index(drop=True)
        text_df = text_df.reset_index(drop=True)
        return pd.concat([X_numeric, text_df], axis=1)

    def train(self, X: pd.DataFrame, y: pd.Series):
        print("  Preparing features...")
        X_combined = self._prepare(X, fit=True)

        # Split interne pour une validation honnête
        X_tr, X_val, y_tr, y_val = train_test_split(
            X_combined, y, test_size=0.1, random_state=42
        )

        print("  Training XGBoost model...")
        self.model.fit(
            X_tr, y_tr,
            eval_set=[(X_val, y_val)],
            verbose=100
        )
        print(f"  Best iteration : {self.model.best_iteration}")
        self.is_trained = True
        print("Model trained successfully!")

    def predict(self, X: pd.DataFrame) -> float:
        """Single sample prediction — returns phishing probability."""
        if not self.is_trained:
            raise Exception("Model is not trained yet. Call train() first.")
        X_combined = self._prepare(X, fit=False)
        return self.model.predict_proba(X_combined)[0][1]

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        """Batch prediction — returns array of shape (n_samples, 2)."""
        if not self.is_trained:
            raise Exception("Model is not trained yet. Call train() first.")
        X_combined = self._prepare(X, fit=False)
        return self.model.predict_proba(X_combined)

    def save(self, model_path: str, vectorizer_path: str):
        joblib.dump(self.model, model_path)
        joblib.dump(self.vectorizer, vectorizer_path)
        print(f"Model saved to {model_path}")
        print(f"Vectorizer saved to {vectorizer_path}")

    def load(self, model_path: str, vectorizer_path: str):
        self.model = joblib.load(model_path)
        self.vectorizer = joblib.load(vectorizer_path)
        self.is_trained = True
        print("Model loaded successfully!")