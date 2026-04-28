# Phishing Detector

Detecteur de phishing base sur le Machine Learning et la Programmation Orientee Objet en Python.
Detecte les URLs et emails de phishing en temps reel depuis nimporte ou dans le terminal.

## Installation rapide

### Linux / Mac

    git clone https://github.com/f3d4yn/phishing-detector.git
    cd phishing-detector
    chmod +x install.sh
    ./install.sh
    source ~/.bashrc

### Windows

    git clone https://github.com/f3d4yn/phishing-detector.git
    cd phishing-detector
    install.bat

Redemarre le terminal apres installation puis tape : isphishing

## Performance du modele

| Metrique   | Score  |
|------------|--------|
| Exactitude | 95.52% |
| Precision  | 95.79% |
| Rappel     | 95.54% |
| F1 Score   | 95.66% |
| ROC AUC    | 98.76% |

Entraine sur 93 916 echantillons (11 430 URLs + 82 486 Emails)

## Architecture POO

- BaseInput    : Classe abstraite (ABC)
- EmailInput   : Heritage + validate()
- URLInput     : Heritage + extract_domain()
- FeatureExtractor : Extraction de 12 features
- MLModel      : Random Forest (100 arbres)
- PhishingDetector : Orchestrateur principal
- ThreatReport : Score + Label + Raisons
- AlertSystem  : Alertes + Logs

## Lancer les tests

    source venv/bin/activate
    python -m unittest discover tests/

## Note sur les datasets

Les datasets et le modele entraine ne sont pas inclus (trop lourds).
Pour entrainer le modele :

1. Telecharge les datasets sur Kaggle :
   - URLs  : Web Page Phishing Detection Dataset
   - Emails: Phishing Email Dataset

2. Place-les dans data/ :
   - data/phishing_dataset.csv
   - data/email_dataset.csv

3. Lance l entrainement :
       python train.py

## Auteurs

Habib Ilyas et Boukyod Abdessamad
Module : Programmation Avancee (Python POO)
