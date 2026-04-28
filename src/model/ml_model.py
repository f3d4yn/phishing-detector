# joblib is used to save and load the trained model to disk
import joblib

# numpy is used for numerical operations
import numpy as np

# pandas is used to handle the dataset
import pandas as pd

# RandomForestClassifier is our main ML algorithm
from sklearn.ensemble import RandomForestClassifier

# TfidfVectorizer converts text into numerical features
from sklearn.feature_extraction.text import TfidfVectorizer

# train_test_split divides the dataset into training and testing sets
from sklearn.model_selection import train_test_split

class MLModel:

    def __init__(self):
        # Initialize the Random Forest model
        # n_estimators=100 means we use 100 decision trees
        # random_state=42 ensures reproducible results every time
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        
        # TF-IDF vectorizer converts cleaned text into numerical vectors
        # max_features=500 means we keep only the 500 most important words
        self.vectorizer = TfidfVectorizer(max_features=500)
        
        # This will be True once the model has been trained
        self.is_trained = False
        
        # Store the accuracy score after training
        self.accuracy = 0.0

    def train(self, X: pd.DataFrame, y: pd.Series):
        # X contains all the features (url_length, suspicious_count, etc.)
        # y contains the labels (0 = legitimate, 1 = phishing)
        
        # Step 1 : fit the TF-IDF vectorizer on the cleaned text column
        # This learns which words are important across all emails/URLs
        text_vectors = self.vectorizer.fit_transform(X['cleaned_text'])
        
        # Step 2 : convert the text vectors to a DataFrame
        text_df = pd.DataFrame(
            text_vectors.toarray(),
            columns=[f"word_{i}" for i in range(text_vectors.shape[1])]
        )
        
        # Step 3 : drop the cleaned_text column from X
        # because the model needs numbers only, not raw text
        X_numeric = X.drop(columns=['cleaned_text'])
        
        # Step 4 : combine numerical features with TF-IDF text features
        X_combined = pd.concat([X_numeric.reset_index(drop=True), text_df], axis=1)
        
        # Step 5 : train the Random Forest model on the combined features
        self.model.fit(X_combined, y)
        
        # Mark the model as trained
        self.is_trained = True
        
        print("Model trained successfully!")

    def predict(self, X: pd.DataFrame) -> float:
        # Make sure the model is trained before predicting
        if not self.is_trained:
            raise Exception("Model is not trained yet. Call train() first.")
        
        # Step 1 : transform the text column using the already fitted vectorizer
        # Note: we use transform() here, NOT fit_transform()
        # because the vectorizer was already fitted during training
        text_vectors = self.vectorizer.transform(X['cleaned_text'])
        
        # Step 2 : convert to DataFrame
        text_df = pd.DataFrame(
            text_vectors.toarray(),
            columns=[f"word_{i}" for i in range(text_vectors.shape[1])]
        )
        
        # Step 3 : drop the cleaned_text column
        X_numeric = X.drop(columns=['cleaned_text'])
        
        # Step 4 : combine numerical and text features
        X_combined = pd.concat([X_numeric.reset_index(drop=True), text_df], axis=1)
        
        # Step 5 : predict the probability of phishing
        # predict_proba returns [[prob_legitimate, prob_phishing]]
        # We return only the phishing probability (index 1)
        probability = self.model.predict_proba(X_combined)[0][1]
        
        return probability

    def save(self, model_path: str, vectorizer_path: str):
        # Save the trained model to disk so we don't have to retrain every time
        joblib.dump(self.model, model_path)
        
        # Save the vectorizer separately — it must match the model exactly
        joblib.dump(self.vectorizer, vectorizer_path)
        
        print(f"Model saved to {model_path}")
        print(f"Vectorizer saved to {vectorizer_path}")

    def load(self, model_path: str, vectorizer_path: str):
        # Load a previously saved model from disk
        self.model = joblib.load(model_path)
        
        # Load the matching vectorizer
        self.vectorizer = joblib.load(vectorizer_path)
        
        # Mark the model as trained since it was already trained before saving
        self.is_trained = True
        
        print("Model loaded successfully!")