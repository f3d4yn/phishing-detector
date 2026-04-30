import re
import nltk

# Auto-download NLTK data if not present
def _ensure_nltk_data():
    packages = ['stopwords', 'punkt', 'punkt_tab']
    for package in packages:
        try:
            nltk.data.find(f'corpora/{package}')
        except LookupError:
            try:
                nltk.data.find(f'tokenizers/{package}')
            except LookupError:
                nltk.download(package, quiet=True)

_ensure_nltk_data()

from nltk.corpus import stopwords
from nltk.stem import PorterStemmer

class TextCleaner:

    def __init__(self):
        self.stop_words = set(stopwords.words("english"))
        self.stemmer = PorterStemmer()

    def remove_html(self, text: str) -> str:
        return re.sub(r'<.*?>', '', text)

    def to_lowercase(self, text: str) -> str:
        return text.lower()

    def remove_special_characters(self, text: str) -> str:
        return re.sub(r'[^a-zA-Z\s]', '', text)

    def remove_stopwords(self, text: str) -> str:
        words = text.split()
        filtered = [word for word in words if word not in self.stop_words]
        return ' '.join(filtered)

    def stem_text(self, text: str) -> str:
        words = text.split()
        stemmed = [self.stemmer.stem(word) for word in words]
        return ' '.join(stemmed)

    def clean(self, text: str) -> str:
        text = self.remove_html(text)
        text = self.to_lowercase(text)
        text = self.remove_special_characters(text)
        text = self.remove_stopwords(text)
        text = self.stem_text(text)
        return text
