"""
Module d'authentification à deux facteurs pour IRIS.
Fournit des fonctionnalités pour la configuration et la vérification 2FA.
"""

import os
import yaml
import logging
import pyotp
import qrcode
from qrcode.constants import ERROR_CORRECT_L
from PIL import Image
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
from datetime import datetime
from typing import Dict, Any, List, Optional, cast

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TwoFactorAuth:
    """Gestionnaire d'authentification à deux facteurs."""
    
    def __init__(self, config_path: str):
        """
        Initialise le gestionnaire 2FA.
        
        Args:
            config_path: Chemin vers le fichier de configuration
        """
        self.config = self._load_config(config_path)
        self.totp = pyotp.TOTP(
            self.config['2fa']['secret'],
            interval=self.config['2fa']['interval']
        )
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Charge la configuration depuis le fichier YAML."""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                if not isinstance(config, dict):
                    raise ValueError("La configuration doit être un dictionnaire")
                return cast(Dict[str, Any], config)
        except Exception as e:
            logger.error(f"Erreur lors du chargement de la configuration: {e}")
            raise
            
    def generate_secret(self) -> str:
        """Génère une nouvelle clé secrète pour 2FA."""
        return pyotp.random_base32()
        
    def generate_qr_code(self, username: str, secret: str) -> str:
        """
        Génère un QR code pour la configuration 2FA.
        
        Args:
            username: Nom d'utilisateur
            secret: Clé secrète
            
        Returns:
            Chemin vers le fichier QR code généré
        """
        try:
            # Génération de l'URI TOTP
            totp = pyotp.TOTP(secret)
            provisioning_uri = totp.provisioning_uri(
                username,
                issuer_name=self.config['2fa']['issuer']
            )
            
            # Création du QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=1,  # Niveau L de correction d'erreur
                box_size=10,
                border=4
            )
            qr.add_data(provisioning_uri)
            qr.make(fit=True)
            
            # Création de l'image
            qr_image = qr.make_image(fill_color="black", back_color="white")
            
            # Sauvegarde du QR code
            qr_dir = self.config['2fa']['qr_directory']
            os.makedirs(qr_dir, exist_ok=True)
            qr_path = os.path.join(qr_dir, f"{username}_2fa.png")
            qr_image.save(qr_path)
            
            logger.info(f"QR code généré pour {username}")
            return qr_path
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération du QR code: {e}")
            raise
            
    def verify_token(self, token: str) -> bool:
        """
        Vérifie un token 2FA.
        
        Args:
            token: Token à vérifier
            
        Returns:
            True si le token est valide, False sinon
        """
        try:
            return self.totp.verify(token)
        except Exception as e:
            logger.error(f"Erreur lors de la vérification du token: {e}")
            return False
            
    def send_sms_code(self, phone_number: str) -> bool:
        """
        Envoie un code 2FA par SMS.
        
        Args:
            phone_number: Numéro de téléphone
            
        Returns:
            True si l'envoi a réussi, False sinon
        """
        if not self.config['2fa']['sms_enabled']:
            logger.warning("L'envoi de SMS est désactivé")
            return False
            
        try:
            code = self.totp.now()
            message = f"Votre code de vérification IRIS est: {code}"
            
            # Configuration Twilio
            account_sid = self.config['2fa']['twilio_sid']
            auth_token = self.config['2fa']['twilio_token']
            from_number = self.config['2fa']['twilio_phone']
            
            # Envoi du SMS via Twilio
            url = f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json"
            data = {
                "From": from_number,
                "To": phone_number,
                "Body": message
            }
            
            response = requests.post(
                url,
                auth=(account_sid, auth_token),
                data=data
            )
            
            if response.status_code == 201:
                logger.info(f"SMS envoyé à {phone_number}")
                return True
            else:
                logger.error(f"Erreur lors de l'envoi du SMS: {response.text}")
                return False
                
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi du SMS: {e}")
            return False
            
    def send_email_code(self, email: str) -> bool:
        """
        Envoie un code 2FA par email.
        
        Args:
            email: Adresse email
            
        Returns:
            True si l'envoi a réussi, False sinon
        """
        try:
            code = self.totp.now()
            
            # Configuration de l'email
            smtp_config = self.config['notifications']['email']
            msg = MIMEMultipart()
            msg['From'] = smtp_config['from_address']
            msg['To'] = email
            msg['Subject'] = "Code de vérification IRIS"
            
            body = f"""
            Bonjour,
            
            Votre code de vérification IRIS est: {code}
            
            Ce code est valide pendant {self.config['2fa']['interval']} secondes.
            
            Cordialement,
            L'équipe IRIS
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Envoi de l'email
            with smtplib.SMTP(smtp_config['smtp_server'], smtp_config['smtp_port']) as server:
                server.starttls()
                server.login(smtp_config['smtp_username'], smtp_config['smtp_password'])
                server.send_message(msg)
                
            logger.info(f"Email envoyé à {email}")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi de l'email: {e}")
            return False
            
    def get_remaining_time(self) -> int:
        """
        Retourne le temps restant avant l'expiration du token actuel.
        
        Returns:
            Nombre de secondes restantes
        """
        return int(self.totp.interval - (datetime.now().timestamp() % self.totp.interval))
        
    def is_token_expired(self) -> bool:
        """
        Vérifie si le token actuel est expiré.
        
        Returns:
            True si le token est expiré, False sinon
        """
        return self.get_remaining_time() < 5  # 5 secondes de marge
        
    def get_backup_codes(self, count: int = 10) -> list:
        """
        Génère des codes de secours.
        
        Args:
            count: Nombre de codes à générer
            
        Returns:
            Liste des codes de secours
        """
        try:
            codes = []
            for _ in range(count):
                code = pyotp.random_base32()[:8].upper()
                codes.append(code)
            return codes
        except Exception as e:
            logger.error(f"Erreur lors de la génération des codes de secours: {e}")
            raise
            
    def verify_backup_code(self, code: str, backup_codes: list) -> bool:
        """
        Vérifie un code de secours.
        
        Args:
            code: Code à vérifier
            backup_codes: Liste des codes de secours valides
            
        Returns:
            True si le code est valide, False sinon
        """
        try:
            if code in backup_codes:
                backup_codes.remove(code)  # Utilisation unique
                return True
            return False
        except Exception as e:
            logger.error(f"Erreur lors de la vérification du code de secours: {e}")
            return False

def main():
    """Fonction principale pour tester le module."""
    try:
        # Initialisation
        auth = TwoFactorAuth("config/secrets.yaml")
        
        # Test de génération de QR code
        username = "test_user"
        secret = auth.generate_secret()
        qr_path = auth.generate_qr_code(username, secret)
        print(f"QR code généré: {qr_path}")
        
        # Test de vérification de token
        token = auth.totp.now()
        is_valid = auth.verify_token(token)
        print(f"Token valide: {is_valid}")
        
        # Test d'envoi de SMS
        phone = "+33612345678"
        sms_sent = auth.send_sms_code(phone)
        print(f"SMS envoyé: {sms_sent}")
        
        # Test d'envoi d'email
        email = "test@example.com"
        email_sent = auth.send_email_code(email)
        print(f"Email envoyé: {email_sent}")
        
        # Test des codes de secours
        backup_codes = auth.get_backup_codes()
        print(f"Codes de secours générés: {backup_codes}")
        
    except Exception as e:
        logger.error(f"Erreur dans la fonction principale: {e}")
        raise

if __name__ == "__main__":
    main() 