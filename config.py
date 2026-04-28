# os is used to build file paths that work on all operating systems
import os

# ============================================================
#   PATHS
# ============================================================

# Root directory of the project (the folder containing config.py)
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

# Path to the data folder containing the datasets
DATA_DIR = os.path.join(ROOT_DIR, "data")

# Path to the models folder where trained models are saved
MODELS_DIR = os.path.join(ROOT_DIR, "models")

# Path to the logs folder where alerts are saved
LOGS_DIR = os.path.join(ROOT_DIR, "logs")

# Full path to the phishing dataset CSV file
DATASET_PATH = os.path.join(DATA_DIR, "phishing_dataset.csv")

# Full path to the trained model file
MODEL_PATH = os.path.join(MODELS_DIR, "model.pkl")

# Full path to the saved TF-IDF vectorizer
VECTORIZER_PATH = os.path.join(MODELS_DIR, "vectorizer.pkl")

# Full path to the alerts log file
LOG_FILE = os.path.join(LOGS_DIR, "alerts.log")

# ============================================================
#   MODEL SETTINGS
# ============================================================

# Minimum phishing score to trigger an alert (between 0 and 1)
# Example: 0.7 means 70% confidence needed to flag as phishing
ALERT_THRESHOLD = 0.7

# Number of decision trees in the Random Forest
N_ESTIMATORS = 100

# Ensures results are reproducible every time you train
RANDOM_STATE = 42

# Maximum number of words to keep in the TF-IDF vectorizer
MAX_FEATURES = 500

# Percentage of data used for testing (0.2 = 20%)
TEST_SIZE = 0.2

# ============================================================
#   SUSPICIOUS WORDS
# ============================================================

# List of words commonly found in phishing emails
# Used by FeatureExtractor to count suspicious words
SUSPICIOUS_WORDS = [
    "verify", "account", "password", "login", "urgent",
    "click", "confirm", "update", "secure", "bank",
    "suspend", "limited", "access", "credential", "alert",
    "immediately", "validate", "expire", "unauthorized"
]