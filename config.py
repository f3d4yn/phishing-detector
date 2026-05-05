import os

# ============================================================
#   PATHS
# ============================================================

ROOT_DIR    = os.path.dirname(os.path.abspath(__file__))
DATA_DIR    = os.path.join(ROOT_DIR, "data")
MODELS_DIR  = os.path.join(ROOT_DIR, "models")
LOGS_DIR    = os.path.join(ROOT_DIR, "logs")

LOG_FILE        = os.path.join(LOGS_DIR, "alerts.log")

# ── modèle unique (legacy) ───────────────────────────────────
MODEL_PATH      = os.path.join(MODELS_DIR, "model.pkl")
VECTORIZER_PATH = os.path.join(MODELS_DIR, "vectorizer.pkl")

# ── modèle URL ───────────────────────────────────────────────
URL_MODEL_PATH      = os.path.join(MODELS_DIR, "model_url.pkl")
URL_VECTORIZER_PATH = os.path.join(MODELS_DIR, "vectorizer_url.pkl")

# ── modèle Email ─────────────────────────────────────────────
EMAIL_MODEL_PATH      = os.path.join(MODELS_DIR, "model_email.pkl")
EMAIL_VECTORIZER_PATH = os.path.join(MODELS_DIR, "vectorizer_email.pkl")

# ============================================================
#   MODEL SETTINGS
# ============================================================

ALERT_THRESHOLD = 0.7
N_ESTIMATORS    = 100
RANDOM_STATE    = 42
MAX_FEATURES    = 500
TEST_SIZE       = 0.2

# ============================================================
#   SUSPICIOUS WORDS
# ============================================================

SUSPICIOUS_WORDS = [
    "verify", "account", "password", "login", "urgent",
    "click", "confirm", "update", "secure", "bank",
    "suspend", "limited", "access", "credential", "alert",
    "immediately", "validate", "expire", "unauthorized"
]