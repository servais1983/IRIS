#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de sécurité pour IRIS.
Fournit des fonctionnalités de sécurité avancées et de détection des menaces.
"""

import os
import sys
import logging
import hashlib
import hmac
import base64
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union, Tuple
import yaml
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import jwt
from passlib.context import CryptContext
import re
import ipaddress
from dataclasses import dataclass
from enum import Enum

# Configuration du logging
log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs')
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, 'security.log')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class SecurityLevel(Enum):
    """Niveaux de sécurité."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class SecurityAlert:
    """Classe pour les alertes de sécurité."""
    timestamp: datetime
    level: SecurityLevel
    source: str
    message: str
    details: Dict
    ip_address: Optional[str] = None
    user_id: Optional[str] = None

class SecurityManager:
    """Gestionnaire de sécurité pour IRIS."""

    def __init__(self, config_path: str = '/etc/iris/security.yaml'):
        """Initialise le gestionnaire de sécurité.

        Args:
            config_path: Chemin vers le fichier de configuration.
        """
        self.config_path = config_path
        self.config = self._load_config()
        self.alerts: List[SecurityAlert] = []
        self._init_crypto()
        self._init_auth()
        self._init_firewall()
        self._rate_limit = {}
        self._max_attempts = 5
        self._lockout_time = 300  # 5 minutes
        self.log_handlers = []

    def _init_logging(self):
        """Initialise le logging."""
        for handler in logger.handlers:
            self.log_handlers.append(handler)

    def cleanup(self):
        """Nettoie les ressources utilisées par le gestionnaire de sécurité."""
        # Fermer les handlers de logging
        for handler in self.log_handlers:
            handler.close()
        self.log_handlers = []

    def _load_config(self) -> dict:
        """Charge la configuration de sécurité.

        Returns:
            Dict contenant la configuration.
        """
        try:
            if not os.path.exists(self.config_path):
                raise FileNotFoundError(f"Fichier de configuration non trouvé: {self.config_path}")
            
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
                if not isinstance(config, dict):
                    raise ValueError("La configuration doit être un dictionnaire")
                
                # Validation des champs requis
                required_fields = ['crypto', 'auth', 'firewall']
                for field in required_fields:
                    if field not in config:
                        raise ValueError(f"Champ requis manquant dans la configuration: {field}")
                
                return config
        except Exception as e:
            logger.error(f"Erreur lors du chargement de la configuration: {str(e)}")
            raise

    def _init_crypto(self) -> None:
        """Initialise les composants cryptographiques."""
        try:
            if 'master_key' not in self.config['crypto']:
                raise ValueError("Clé maître manquante dans la configuration")
            
            # Génération de la clé de chiffrement avec un sel unique
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(self.config['crypto']['master_key'].encode()))
            self.cipher = Fernet(key)

            # Génération des clés RSA avec une taille de clé sécurisée
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096  # Augmentation de la taille de clé pour plus de sécurité
            )
            self.public_key = self.private_key.public_key()
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation crypto: {str(e)}")
            raise

    def _init_auth(self) -> None:
        """Initialise le système d'authentification."""
        try:
            if 'jwt_secret' not in self.config['auth']:
                raise ValueError("Secret JWT manquant dans la configuration")
            
            self.pwd_context = CryptContext(
                schemes=["bcrypt"],
                deprecated="auto",
                bcrypt__rounds=12
            )
            self.jwt_secret = self.config['auth']['jwt_secret']
            self.jwt_algorithm = "HS256"
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation auth: {str(e)}")
            raise

    def _init_firewall(self) -> None:
        """Initialise le pare-feu."""
        try:
            self.allowed_ips = set()
            self.blocked_ips = set()
            self._load_ip_rules()
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation firewall: {str(e)}")
            raise

    def _load_ip_rules(self) -> None:
        """Charge les règles IP."""
        try:
            if 'allowed_ips' not in self.config['firewall'] or 'blocked_ips' not in self.config['firewall']:
                raise ValueError("Règles IP manquantes dans la configuration")
            
            for ip in self.config['firewall']['allowed_ips']:
                self.allowed_ips.add(ipaddress.ip_network(ip))
            for ip in self.config['firewall']['blocked_ips']:
                self.blocked_ips.add(ipaddress.ip_network(ip))
        except Exception as e:
            logger.error(f"Erreur lors du chargement des règles IP: {str(e)}")
            raise

    def encrypt_data(self, data: Union[str, bytes]) -> bytes:
        """Chiffre des données.

        Args:
            data: Données à chiffrer.

        Returns:
            Données chiffrées.
        """
        try:
            if not data:
                raise ValueError("Données vides")
            
            if isinstance(data, str):
                data = data.encode()
            return self.cipher.encrypt(data)
        except Exception as e:
            logger.error(f"Erreur lors du chiffrement: {str(e)}")
            raise

    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Déchiffre des données.

        Args:
            encrypted_data: Données chiffrées.

        Returns:
            Données déchiffrées.
        """
        try:
            if not encrypted_data:
                raise ValueError("Données chiffrées vides")
            
            return self.cipher.decrypt(encrypted_data)
        except Exception as e:
            logger.error(f"Erreur lors du déchiffrement: {str(e)}")
            raise

    def hash_password(self, password: str) -> str:
        """Hache un mot de passe.

        Args:
            password: Mot de passe à hacher.

        Returns:
            Hash du mot de passe.
        """
        try:
            if not password:
                raise ValueError("Mot de passe vide")
            
            if len(password) < 8:
                raise ValueError("Le mot de passe doit contenir au moins 8 caractères")
            
            return self.pwd_context.hash(password)
        except Exception as e:
            logger.error(f"Erreur lors du hachage du mot de passe: {str(e)}")
            raise

    def verify_password(self, password: str, hashed: str) -> bool:
        """Vérifie un mot de passe.

        Args:
            password: Mot de passe à vérifier.
            hashed: Hash à comparer.

        Returns:
            True si le mot de passe est correct.
        """
        try:
            if not password or not hashed:
                raise ValueError("Mot de passe ou hash vide")
            
            return self.pwd_context.verify(password, hashed)
        except Exception as e:
            logger.error(f"Erreur lors de la vérification du mot de passe: {str(e)}")
            raise

    def generate_token(self, data: dict) -> str:
        """Génère un token JWT."""
        return jwt.encode(data, self.jwt_secret, algorithm=self.jwt_algorithm)

    def verify_token(self, token: str) -> dict:
        """Vérifie un token JWT."""
        try:
            return jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
        except jwt.ExpiredSignatureError:
            raise ValueError("Token expiré")
        except jwt.InvalidTokenError:
            raise ValueError("Token invalide")

    def check_ip(self, ip: str) -> bool:
        """Vérifie si une IP est autorisée.

        Args:
            ip: IP à vérifier.

        Returns:
            True si l'IP est autorisée.
        """
        try:
            if not ip:
                raise ValueError("IP vide")
            
            ip_obj = ipaddress.ip_address(ip)
            
            # Vérifier d'abord les IPs bloquées
            for blocked in self.blocked_ips:
                if ip_obj in blocked:
                    return False
            
            # Si des IPs sont autorisées, vérifier qu'elle est dans la liste
            if self.allowed_ips:
                for allowed in self.allowed_ips:
                    if ip_obj in allowed:
                        return True
                return False
            
            return True
        except Exception as e:
            logger.error(f"Erreur lors de la vérification de l'IP: {str(e)}")
            raise

    def add_security_alert(self, level: SecurityLevel, source: str, message: str,
                          details: Dict, ip_address: Optional[str] = None,
                          user_id: Optional[str] = None) -> None:
        """Ajoute une alerte de sécurité.

        Args:
            level: Niveau de l'alerte.
            source: Source de l'alerte.
            message: Message de l'alerte.
            details: Détails supplémentaires.
            ip_address: IP concernée.
            user_id: ID de l'utilisateur concerné.
        """
        try:
            if not message:
                raise ValueError("Message d'alerte vide")
            
            alert = SecurityAlert(
                timestamp=datetime.now(),
                level=level,
                source=source,
                message=message,
                details=details,
                ip_address=ip_address,
                user_id=user_id
            )
            self.alerts.append(alert)
            logger.warning(f"Alerte de sécurité: {message}")
            self._handle_alert(alert)
        except Exception as e:
            logger.error(f"Erreur lors de l'ajout de l'alerte: {str(e)}")
            raise

    def _handle_alert(self, alert: SecurityAlert) -> None:
        """Gère une alerte de sécurité.

        Args:
            alert: Alerte à gérer.
        """
        try:
            if alert.level in [SecurityLevel.HIGH, SecurityLevel.CRITICAL]:
                # Actions immédiates
                if alert.ip_address:
                    self.blocked_ips.add(ipaddress.ip_network(alert.ip_address))
                # Notification
                self._send_alert_notification(alert)
        except Exception as e:
            logger.error(f"Erreur lors de la gestion de l'alerte: {str(e)}")
            raise

    def _send_alert_notification(self, alert: SecurityAlert) -> None:
        """Envoie une notification d'alerte.

        Args:
            alert: Alerte à notifier.
        """
        try:
            # Implémentation de l'envoi de notification
            # (email, Slack, etc.)
            pass
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi de la notification: {str(e)}")
            raise

    def validate_input(self, data: str, pattern: str) -> bool:
        """Valide une entrée selon un motif.

        Args:
            data: Données à valider.
            pattern: Type de validation ('ip', 'email', etc.).

        Returns:
            True si les données sont valides.
        """
        try:
            if not data:
                return False

            if pattern == 'ip':
                try:
                    ip = ipaddress.ip_address(data)
                    return True
                except ValueError:
                    return False
            elif pattern == 'email':
                email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                return bool(re.match(email_pattern, data))
            elif pattern == 'url':
                url_pattern = r'^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$'
                return bool(re.match(url_pattern, data))
            else:
                return False
        except Exception as e:
            logger.error(f"Erreur lors de la validation: {str(e)}")
            return False

    def sanitize_output(self, data: str) -> str:
        """Nettoie une sortie.

        Args:
            data: Données à nettoyer.

        Returns:
            Données nettoyées.
        """
        try:
            if not data:
                return ""
            
            # Suppression des caractères dangereux et échappement HTML
            data = re.sub(r'[<>]', '', data)
            data = data.replace('&', '&amp;')
            data = data.replace('"', '&quot;')
            data = data.replace("'", '&#x27;')
            return data
        except Exception as e:
            logger.error(f"Erreur lors du nettoyage des données: {str(e)}")
            raise

    def check_rate_limit(self, key: str) -> bool:
        """Vérifie si une action est autorisée selon la limitation de taux.

        Args:
            key: Clé unique pour l'action (ex: 'login_127.0.0.1').

        Returns:
            True si l'action est autorisée.
        """
        try:
            current_time = time.time()
            
            # Initialiser ou réinitialiser le compteur si nécessaire
            if key not in self._rate_limit:
                self._rate_limit[key] = {
                    'count': 1,
                    'last_attempt': current_time
                }
                return True
            
            # Vérifier si le délai de verrouillage est expiré
            if current_time - self._rate_limit[key]['last_attempt'] > self._lockout_time:
                self._rate_limit[key] = {
                    'count': 1,
                    'last_attempt': current_time
                }
                return True
            
            # Vérifier si le nombre maximum de tentatives est atteint
            if self._rate_limit[key]['count'] >= self._max_attempts:
                return False
            
            # Incrémenter le compteur et mettre à jour le timestamp
            self._rate_limit[key]['count'] += 1
            self._rate_limit[key]['last_attempt'] = current_time
            
            # Retourner False si c'est la 5ème tentative
            return self._rate_limit[key]['count'] < self._max_attempts
        except Exception as e:
            logger.error(f"Erreur lors de la vérification de la limitation de taux: {str(e)}")
            return False

    def test_rate_limiting(self):
        """Test de la limitation de taux"""
        key = 'login_127.0.0.1'
        
        # Simuler plusieurs tentatives
        for _ in range(4):
            self.assertTrue(self.check_rate_limit(key))
        
        # La 5ème tentative devrait être bloquée
        self.assertFalse(self.check_rate_limit(key))
        
        # Attendre que le délai expire
        self._rate_limit[key]['last_attempt'] = 0
        self.assertTrue(self.check_rate_limit(key))

def main():
    """Fonction principale."""
    try:
        security_manager = SecurityManager()
        # Exemple d'utilisation
        security_manager.add_security_alert(
            SecurityLevel.HIGH,
            "auth",
            "Tentative de connexion échouée multiple",
            {"attempts": 5, "username": "admin"},
            ip_address="192.168.1.1"
        )
    except Exception as e:
        logger.error(f"Erreur dans la fonction principale: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main() 