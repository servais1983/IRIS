"""
Module de rotation des clés de chiffrement pour IRIS.
Fournit des fonctionnalités pour la gestion et la rotation automatique des clés.
"""

import os
import yaml
import logging
import json
import datetime
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf import pbkdf2
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import base64
import threading
import time
import schedule

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class KeyType(Enum):
    """Types de clés."""
    SYMMETRIC = "symmetric"
    ASYMMETRIC = "asymmetric"
    MASTER = "master"

@dataclass
class KeyMetadata:
    """Métadonnées d'une clé."""
    id: str
    type: KeyType
    created_at: datetime.datetime
    expires_at: datetime.datetime
    version: int
    status: str
    algorithm: str
    size: int

class KeyManager:
    """Gestionnaire de clés de chiffrement."""
    
    def __init__(self, config_path: str):
        """
        Initialise le gestionnaire de clés.
        
        Args:
            config_path: Chemin vers le fichier de configuration
        """
        self.config = self._load_config(config_path)
        self.keys_dir = self.config['keys']['directory']
        self.metadata_file = os.path.join(self.keys_dir, 'metadata.json')
        self.keys: Dict[str, Any] = {}
        self.metadata: Dict[str, KeyMetadata] = {}
        self._init_keys()
        self._start_rotation_scheduler()
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Charge la configuration depuis le fichier YAML.
        
        Args:
            config_path: Chemin vers le fichier de configuration.
            
        Returns:
            Dict[str, Any]: Configuration chargée.
            
        Raises:
            ValueError: Si la configuration n'est pas un dictionnaire.
        """
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                if not isinstance(config, dict):
                    raise ValueError("La configuration doit être un dictionnaire")
                return config
        except Exception as e:
            logger.error(f"Erreur lors du chargement de la configuration: {e}")
            raise
            
    def _init_keys(self):
        """Initialise les clés et les métadonnées."""
        try:
            os.makedirs(self.keys_dir, exist_ok=True)
            
            # Chargement des métadonnées
            if os.path.exists(self.metadata_file):
                with open(self.metadata_file, 'r') as f:
                    metadata = json.load(f)
                    for key_id, meta in metadata.items():
                        self.metadata[key_id] = KeyMetadata(
                            id=key_id,
                            type=KeyType(meta['type']),
                            created_at=datetime.datetime.fromisoformat(meta['created_at']),
                            expires_at=datetime.datetime.fromisoformat(meta['expires_at']),
                            version=meta['version'],
                            status=meta['status'],
                            algorithm=meta['algorithm'],
                            size=meta['size']
                        )
                        
            # Génération des clés manquantes
            self._generate_missing_keys()
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation des clés: {e}")
            raise
            
    def _generate_missing_keys(self):
        """Génère les clés manquantes."""
        try:
            # Clé maîtresse
            if not self._has_key(KeyType.MASTER):
                self._generate_master_key()
                
            # Clés symétriques
            if not self._has_key(KeyType.SYMMETRIC):
                self._generate_symmetric_key()
                
            # Clés asymétriques
            if not self._has_key(KeyType.ASYMMETRIC):
                self._generate_asymmetric_key()
                
        except Exception as e:
            logger.error(f"Erreur lors de la génération des clés manquantes: {e}")
            raise
            
    def _has_key(self, type_: KeyType) -> bool:
        """
        Vérifie si une clé existe.
        
        Args:
            type_: Type de clé
            
        Returns:
            True si la clé existe, False sinon
        """
        return any(meta.type == type_ and meta.status == 'active' 
                  for meta in self.metadata.values())
                  
    def _generate_master_key(self):
        """Génère une nouvelle clé maîtresse."""
        try:
            key = Fernet.generate_key()
            key_id = f"master_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
            
            # Sauvegarde de la clé
            key_path = os.path.join(self.keys_dir, f"{key_id}.key")
            with open(key_path, 'wb') as f:
                f.write(key)
                
            # Création des métadonnées
            metadata = KeyMetadata(
                id=key_id,
                type=KeyType.MASTER,
                created_at=datetime.datetime.now(),
                expires_at=datetime.datetime.now() + datetime.timedelta(
                    days=self.config['keys']['master_key']['rotation_days']
                ),
                version=1,
                status='active',
                algorithm='AES-256-GCM',
                size=256
            )
            
            self.metadata[key_id] = metadata
            self.keys[key_id] = key
            
            self._save_metadata()
            logger.info(f"Nouvelle clé maîtresse générée: {key_id}")
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération de la clé maîtresse: {e}")
            raise
            
    def _generate_symmetric_key(self):
        """Génère une nouvelle clé symétrique."""
        try:
            key = Fernet.generate_key()
            key_id = f"symmetric_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
            
            # Sauvegarde de la clé
            key_path = os.path.join(self.keys_dir, f"{key_id}.key")
            with open(key_path, 'wb') as f:
                f.write(key)
                
            # Création des métadonnées
            metadata = KeyMetadata(
                id=key_id,
                type=KeyType.SYMMETRIC,
                created_at=datetime.datetime.now(),
                expires_at=datetime.datetime.now() + datetime.timedelta(
                    days=self.config['keys']['symmetric_key']['rotation_days']
                ),
                version=1,
                status='active',
                algorithm='AES-256-GCM',
                size=256
            )
            
            self.metadata[key_id] = metadata
            self.keys[key_id] = key
            
            self._save_metadata()
            logger.info(f"Nouvelle clé symétrique générée: {key_id}")
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération de la clé symétrique: {e}")
            raise
            
    def _generate_asymmetric_key(self):
        """Génère une nouvelle paire de clés asymétriques."""
        try:
            # Génération de la paire de clés
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            public_key = private_key.public_key()
            
            key_id = f"asymmetric_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
            
            # Sauvegarde des clés
            private_path = os.path.join(self.keys_dir, f"{key_id}_private.pem")
            public_path = os.path.join(self.keys_dir, f"{key_id}_public.pem")
            
            # Sauvegarde de la clé privée
            with open(private_path, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(
                        self._get_master_key()
                    )
                ))
                
            # Sauvegarde de la clé publique
            with open(public_path, 'wb') as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
                
            # Création des métadonnées
            metadata = KeyMetadata(
                id=key_id,
                type=KeyType.ASYMMETRIC,
                created_at=datetime.datetime.now(),
                expires_at=datetime.datetime.now() + datetime.timedelta(
                    days=self.config['keys']['asymmetric_key']['rotation_days']
                ),
                version=1,
                status='active',
                algorithm='RSA',
                size=2048
            )
            
            self.metadata[key_id] = metadata
            self.keys[key_id] = {
                'private': private_key,
                'public': public_key
            }
            
            self._save_metadata()
            logger.info(f"Nouvelle paire de clés asymétriques générée: {key_id}")
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération des clés asymétriques: {e}")
            raise
            
    def _get_master_key(self) -> bytes:
        """
        Récupère la clé maîtresse active.
        
        Returns:
            Clé maîtresse
        """
        try:
            for key_id, meta in self.metadata.items():
                if meta.type == KeyType.MASTER and meta.status == 'active':
                    if key_id not in self.keys:
                        key_path = os.path.join(self.keys_dir, f"{key_id}.key")
                        with open(key_path, 'rb') as f:
                            self.keys[key_id] = f.read()
                    return self.keys[key_id]
            raise ValueError("Aucune clé maîtresse active trouvée")
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de la clé maîtresse: {e}")
            raise
            
    def _save_metadata(self):
        """Sauvegarde les métadonnées."""
        try:
            metadata = {
                key_id: {
                    'type': meta.type.value,
                    'created_at': meta.created_at.isoformat(),
                    'expires_at': meta.expires_at.isoformat(),
                    'version': meta.version,
                    'status': meta.status,
                    'algorithm': meta.algorithm,
                    'size': meta.size
                }
                for key_id, meta in self.metadata.items()
            }
            
            with open(self.metadata_file, 'w') as f:
                json.dump(metadata, f, indent=2)
                
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde des métadonnées: {e}")
            raise
            
    def _start_rotation_scheduler(self):
        """Démarre le planificateur de rotation des clés."""
        try:
            # Vérification quotidienne
            schedule.every().day.at("00:00").do(self._check_key_rotation)
            
            # Démarrage du thread de planification
            def run_scheduler():
                while True:
                    schedule.run_pending()
                    time.sleep(60)
                    
            thread = threading.Thread(target=run_scheduler, daemon=True)
            thread.start()
            
        except Exception as e:
            logger.error(f"Erreur lors du démarrage du planificateur: {e}")
            raise
            
    def _check_key_rotation(self):
        """Vérifie et effectue la rotation des clés."""
        try:
            now = datetime.datetime.now()
            
            for key_id, meta in list(self.metadata.items()):
                # Vérification de l'expiration
                if meta.status == 'active' and now >= meta.expires_at:
                    self._rotate_key(key_id)
                    
                # Vérification de la période de grâce
                grace_period = datetime.timedelta(
                    days=self.config['keys']['grace_period_days']
                )
                if (meta.status == 'active' and 
                    now >= meta.expires_at - grace_period):
                    self._notify_key_expiration(key_id)
                    
        except Exception as e:
            logger.error(f"Erreur lors de la vérification de la rotation: {e}")
            raise
            
    def _rotate_key(self, key_id: str):
        """
        Effectue la rotation d'une clé.
        
        Args:
            key_id: Identifiant de la clé
        """
        try:
            meta = self.metadata[key_id]
            
            # Génération de la nouvelle clé
            if meta.type == KeyType.MASTER:
                self._generate_master_key()
            elif meta.type == KeyType.SYMMETRIC:
                self._generate_symmetric_key()
            elif meta.type == KeyType.ASYMMETRIC:
                self._generate_asymmetric_key()
                
            # Mise à jour du statut de l'ancienne clé
            meta.status = 'deprecated'
            self._save_metadata()
            
            logger.info(f"Rotation de la clé {key_id} effectuée")
            
        except Exception as e:
            logger.error(f"Erreur lors de la rotation de la clé {key_id}: {e}")
            raise
            
    def _notify_key_expiration(self, key_id: str):
        """
        Notifie l'expiration prochaine d'une clé.
        
        Args:
            key_id: Identifiant de la clé
        """
        try:
            meta = self.metadata[key_id]
            days_remaining = (meta.expires_at - datetime.datetime.now()).days
            
            message = (
                f"La clé {key_id} ({meta.type.value}) expirera dans {days_remaining} jours. "
                f"Une nouvelle clé sera générée automatiquement."
            )
            
            # Envoi de la notification
            if self.config['notifications']['enabled']:
                self._send_notification(message)
                
            logger.warning(message)
            
        except Exception as e:
            logger.error(f"Erreur lors de la notification d'expiration: {e}")
            
    def _send_notification(self, message: str):
        """
        Envoie une notification.
        
        Args:
            message: Message à envoyer
        """
        try:
            config = self.config['notifications']
            
            # Envoi par email
            if config['email']['enabled']:
                # Implémentation de l'envoi d'email
                pass
                
            # Envoi par Slack
            if config['slack']['enabled']:
                # Implémentation de l'envoi Slack
                pass
                
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi de la notification: {e}")
            
    def get_active_key(self, type_: KeyType) -> Any:
        """
        Récupère la clé active d'un type donné.
        
        Args:
            type_: Type de clé
            
        Returns:
            Clé active
        """
        try:
            for key_id, meta in self.metadata.items():
                if meta.type == type_ and meta.status == 'active':
                    if key_id not in self.keys:
                        if type_ == KeyType.ASYMMETRIC:
                            # Chargement des clés asymétriques
                            private_path = os.path.join(self.keys_dir, f"{key_id}_private.pem")
                            public_path = os.path.join(self.keys_dir, f"{key_id}_public.pem")
                            
                            with open(private_path, 'rb') as f:
                                private_key = serialization.load_pem_private_key(
                                    f.read(),
                                    password=self._get_master_key()
                                )
                                
                            with open(public_path, 'rb') as f:
                                public_key = serialization.load_pem_public_key(f.read())
                                
                            self.keys[key_id] = {
                                'private': private_key,
                                'public': public_key
                            }
                        else:
                            # Chargement des autres types de clés
                            key_path = os.path.join(self.keys_dir, f"{key_id}.key")
                            with open(key_path, 'rb') as f:
                                self.keys[key_id] = f.read()
                                
                    return self.keys[key_id]
                    
            raise ValueError(f"Aucune clé active de type {type_.value} trouvée")
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération de la clé active: {e}")
            raise

def main():
    """Fonction principale pour tester le module."""
    try:
        # Initialisation
        key_manager = KeyManager("config/secrets.yaml")
        
        # Test de récupération des clés
        master_key = key_manager.get_active_key(KeyType.MASTER)
        print(f"Clé maîtresse récupérée: {len(master_key)} bytes")
        
        symmetric_key = key_manager.get_active_key(KeyType.SYMMETRIC)
        print(f"Clé symétrique récupérée: {len(symmetric_key)} bytes")
        
        asymmetric_keys = key_manager.get_active_key(KeyType.ASYMMETRIC)
        print("Clés asymétriques récupérées")
        
        # Attente pour tester la rotation
        print("Attente de 5 secondes pour tester la rotation...")
        time.sleep(5)
        
    except Exception as e:
        logger.error(f"Erreur dans la fonction principale: {e}")
        raise

if __name__ == "__main__":
    main() 