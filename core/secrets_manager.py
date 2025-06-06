#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de gestion des secrets pour IRIS.
Fournit des fonctionnalités de gestion sécurisée des secrets et des clés.
"""

import os
import logging
import json
from typing import Dict, Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/secrets.log'),
    ]
)

logger = logging.getLogger(__name__)

class SecretsManager:
    """Gestionnaire de secrets pour IRIS."""

    def __init__(self, config_path: str = 'config/secrets.yaml'):
        """Initialise le gestionnaire de secrets.

        Args:
            config_path: Chemin vers le fichier de configuration.
        """
        self.config_path = config_path
        self.secrets: Dict[str, str] = {}
        self._init_crypto()

    def _init_crypto(self) -> None:
        """Initialise les composants cryptographiques."""
        try:
            # Génération de la clé de chiffrement
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(b"master_key"))  # À remplacer par une vraie clé maître
            self.cipher = Fernet(key)
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation crypto: {str(e)}")
            raise

    def store_secret(self, key: str, value: str) -> None:
        """Stocke un secret de manière sécurisée.

        Args:
            key: Clé du secret.
            value: Valeur à stocker.
        """
        try:
            encrypted_value = self.cipher.encrypt(value.encode())
            self.secrets[key] = base64.b64encode(encrypted_value).decode()
            self._save_secrets()
        except Exception as e:
            logger.error(f"Erreur lors du stockage du secret: {str(e)}")
            raise

    def get_secret(self, key: str) -> Optional[str]:
        """Récupère un secret.

        Args:
            key: Clé du secret.

        Returns:
            La valeur du secret ou None si non trouvé.
        """
        try:
            if key not in self.secrets:
                return None
            encrypted_value = base64.b64decode(self.secrets[key])
            return self.cipher.decrypt(encrypted_value).decode()
        except Exception as e:
            logger.error(f"Erreur lors de la récupération du secret: {str(e)}")
            return None

    def _save_secrets(self) -> None:
        """Sauvegarde les secrets dans un fichier."""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.secrets, f)
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde des secrets: {str(e)}")
            raise

    def _load_secrets(self) -> None:
        """Charge les secrets depuis un fichier."""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r') as f:
                    self.secrets = json.load(f)
        except Exception as e:
            logger.error(f"Erreur lors du chargement des secrets: {str(e)}")
            raise 