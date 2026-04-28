import unittest
import pandas as pd

# Import the classes we want to test
from src.model.ml_model import MLModel
from src.model.evaluator import Evaluator

class TestMLModel(unittest.TestCase):

    def setUp(self):
        # setUp() runs before every single test
        # We create a fresh model for each test
        self.model = MLModel()

    def test_model_not_trained_initially(self):
        # A new model should not be trained yet
        self.assertFalse(self.model.is_trained)

    def test_predict_before_training_raises_error(self):
        # Calling predict() before training should raise an Exception
        X = pd.DataFrame([{
            "url_length": 50,
            "has_at_symbol": 0,
            "has_ip": 0,
            "is_https": 1,
            "subdomain_count": 1,
            "special_chars": 2,
            "domain_length": 6,
            "word_count": 10,
            "suspicious_count": 1,
            "has_url_in_text": 0,
            "has_phone": 0,
            "cleaned_text": "verify account login"
        }])
        # assertRaises checks that the Exception is raised
        with self.assertRaises(Exception):
            self.model.predict(X)

    def test_predict_returns_float(self):
        # After training, predict() should return a float between 0 and 1
        
        # Create a tiny fake dataset for testing
        X = pd.DataFrame([
            {
                "url_length": 80, "has_at_symbol": 1, "has_ip": 0,
                "is_https": 0, "subdomain_count": 3, "special_chars": 5,
                "domain_length": 15, "word_count": 20, "suspicious_count": 5,
                "has_url_in_text": 1, "has_phone": 0,
                "cleaned_text": "verify account password login urgent"
            },
            {
                "url_length": 20, "has_at_symbol": 0, "has_ip": 0,
                "is_https": 1, "subdomain_count": 0, "special_chars": 1,
                "domain_length": 6, "word_count": 5, "suspicious_count": 0,
                "has_url_in_text": 0, "has_phone": 0,
                "cleaned_text": "hello welcome home"
            }
        ])
        y = pd.Series([1, 0])
        
        # Train the model on the fake data
        self.model.train(X, y)
        
        # Predict on the first sample
        score = self.model.predict(X.iloc[[0]])
        
        # Score must be a float between 0 and 1
        self.assertIsInstance(score, float)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)

    def test_model_is_trained_after_train(self):
        # After calling train(), is_trained should be True
        X = pd.DataFrame([
            {
                "url_length": 80, "has_at_symbol": 1, "has_ip": 0,
                "is_https": 0, "subdomain_count": 3, "special_chars": 5,
                "domain_length": 15, "word_count": 20, "suspicious_count": 5,
                "has_url_in_text": 1, "has_phone": 0,
                "cleaned_text": "verify account urgent"
            },
            {
                "url_length": 20, "has_at_symbol": 0, "has_ip": 0,
                "is_https": 1, "subdomain_count": 0, "special_chars": 1,
                "domain_length": 6, "word_count": 5, "suspicious_count": 0,
                "has_url_in_text": 0, "has_phone": 0,
                "cleaned_text": "hello welcome"
            }
        ])
        y = pd.Series([1, 0])
        self.model.train(X, y)
        self.assertTrue(self.model.is_trained)


# This runs all tests when you execute this file directly
if __name__ == "__main__":
    unittest.main()