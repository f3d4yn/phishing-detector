import os
import json
from datetime import datetime

class AlertSystem:

    def __init__(self, threshold: float = 0.7, log_file: str = "logs/alerts.log"):
        # Le seuil qui détermine si on affiche en ROUGE ou en VERT
        self.threshold = threshold
        self.log_file = log_file
        
        # Création du dossier de logs s'il n'existe pas
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        # Codes de couleurs ANSI pour le terminal Kali
        self.RED = '\033[91m'
        self.GREEN = '\033[92m'
        self.BOLD = '\033[1m'
        self.END = '\033[0m'

    def send_alert(self, report) -> None:
        """Affiche le rapport d'analyse dans le terminal avec des couleurs."""
        # On détermine la couleur et le titre selon le score par rapport au seuil
        if report.score >= self.threshold:
            color = self.RED
            status_text = "PHISHING ALERT DETECTED"
        else:
            color = self.GREEN
            status_text = "SITE OR EMAIL LOOKS SAFE"

        # Affichage de l'en-tête du bloc
        print(f"\n{color}{self.BOLD}" + "=" * 50)
        print(f"{status_text:^50}")
        print("=" * 50 + f"{self.END}")
        
        # Détails du score et du label
        print(f"{color}Score     : {report.score:.2%}")
        print(f"Label     : {report.label}")
        
        # Affichage des raisons ou notes techniques (ex: HTTPS)
        if report.reasons:
            reasons_text = ", ".join(report.reasons)
            print(f"{self.END}Note      : {reasons_text}")
        
        # Horodatage
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"{self.END}Time      : {current_time}")
        
        # Pied de page du bloc
        print(f"{color}{self.BOLD}" + "=" * 50 + f"{self.END}\n")

        # On enregistre dans le fichier log uniquement si c'est une menace
        if report.score >= self.threshold:
            self.log_event(report)

    def log_event(self, report) -> None:
        """Enregistre l'alerte dans un fichier JSON pour l'historique."""
        try:
            # Vérification si is_phishing est une méthode ou un attribut
            is_phishing_val = report.is_phishing() if callable(getattr(report, 'is_phishing', None)) else report.is_phishing
            
            log_entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "score": report.score,
                "label": report.label,
                "reasons": report.reasons,
                "is_phishing": is_phishing_val
            }
            
            # Ajout au fichier log en mode 'append'
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            print(f"{self.RED}[!] Failed to log event: {e}{self.END}")