#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de collecte d'artefacts pour IRIS.
"""

import os
import sys
import shutil
import logging
import platform
import glob
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
from pathlib import Path
from core.utils import log_event, calculate_file_hash, create_chain_of_custody
import time

# Imports conditionnels pour Windows
if platform.system() == "Windows":
    try:
        import win32security
        import ntsecuritycon
        import ctypes
        from ctypes import wintypes
    except ImportError:
        logging.warning("Modules Windows non disponibles. Certaines fonctionnalités seront limitées.")
        win32security = None
        ntsecuritycon = None
        ctypes = None
else:
    win32security = None
    ntsecuritycon = None
    ctypes = None

from .utils import setup_logging, calculate_file_hash

class ArtifactCollector:
    """Collecteur d'artefacts système"""
    
    def __init__(self, output_dir: str):
        self.logger = logging.getLogger(__name__)
        self.output_dir = output_dir
        self.system = platform.system().lower()
        self.max_retries = 3
        self.retry_delay = 1  # secondes
        self.is_admin = self._is_admin()
        self.log_handler = None
        
        # Définir les chemins selon le système
        if self.system == 'windows':
            self.log_paths = [
                os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'winevt', 'Logs'),
                os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'Logs'),
                os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'debug')
            ]
            self.config_paths = [
                os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'config'),
                os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32', 'drivers', 'etc')
            ]
            self.prefetch_path = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'Prefetch')
            self.startup_paths = [
                os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
                os.path.join(os.environ.get('ProgramData', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'StartUp')
            ]
        else:
            self.log_paths = ['/var/log', '/var/log/audit']
            self.config_paths = ['/etc']
            self.prefetch_path = None
            self.startup_paths = ['/etc/init.d', '/etc/rc.local']
        
        self.collected_artifacts = []
        self.failed_artifacts = []
        
        # Créer le répertoire de sortie s'il n'existe pas
        os.makedirs(output_dir, exist_ok=True)
    
    def _is_admin(self) -> bool:
        """Vérifie si l'utilisateur a les droits administrateur"""
        try:
            if self.system == 'windows':
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                # Utiliser une approche plus robuste pour Linux
                try:
                    return os.access('/', os.W_OK)
                except Exception:
                    return False
        except Exception as e:
            self.logger.error(f"Erreur lors de la vérification des droits admin: {str(e)}")
            return False
    
    def _get_file_permissions(self, file_path: str) -> Dict[str, Any]:
        """Récupère les permissions d'un fichier"""
        try:
            if self.system == 'windows':
                try:
                    sd = win32security.GetFileSecurity(
                        file_path, 
                        win32security.OWNER_SECURITY_INFORMATION | 
                        win32security.GROUP_SECURITY_INFORMATION |
                        win32security.DACL_SECURITY_INFORMATION
                    )
                    
                    # Récupérer les informations de sécurité de manière sécurisée
                    owner_info = {"name": "Unknown", "sid": None}
                    group_info = {"name": "Unknown", "sid": None}
                    
                    try:
                        owner_sid = sd.GetSecurityDescriptorOwner()
                        owner_info = {
                            "name": win32security.LookupAccountSid("", owner_sid)[0],
                            "sid": str(owner_sid)
                        }
                    except Exception:
                        pass
                        
                    try:
                        group_sid = sd.GetSecurityDescriptorGroup()
                        group_info = {
                            "name": win32security.LookupAccountSid("", group_sid)[0],
                            "sid": str(group_sid)
                        }
                    except Exception:
                        pass
                    
                    return {
                        "owner": owner_info["name"],
                        "group": group_info["name"],
                        "permissions": "Windows ACL"
                    }
                except Exception as e:
                    self.logger.error(f"Erreur lors de la récupération des permissions Windows: {str(e)}")
                    return {"owner": "Unknown", "group": "Unknown", "permissions": "Unknown"}
            else:
                try:
                    stat = os.stat(file_path)
                    return {
                        "owner": stat.st_uid,
                        "group": stat.st_gid,
                        "permissions": oct(stat.st_mode)[-3:]
                    }
                except Exception as e:
                    self.logger.error(f"Erreur lors de la récupération des permissions Unix: {str(e)}")
                    return {"owner": "Unknown", "group": "Unknown", "permissions": "Unknown"}
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des permissions de {file_path}: {str(e)}")
            return {"owner": "Unknown", "group": "Unknown", "permissions": "Unknown"}
    
    def _create_output_dirs(self):
        """Crée les répertoires de sortie"""
        dirs = ['logs', 'config', 'recent', 'prefetch', 'startup']
        for dir_name in dirs:
            dir_path = os.path.join(self.output_dir, dir_name)
            os.makedirs(dir_path, exist_ok=True)
    
    def _collect_logs(self, results: Dict[str, Any]):
        """Collecte les logs système"""
        for log_path in self.log_paths:
            if os.path.exists(log_path):
                for root, _, files in os.walk(log_path):
                    for file in files:
                        if file.endswith(('.log', '.evtx', '.evt')):
                            self._copy_file_with_retry(
                                os.path.join(root, file),
                                os.path.join(self.output_dir, 'logs', file),
                                results
                            )
    
    def _collect_configs(self, results: Dict[str, Any]):
        """Collecte les fichiers de configuration"""
        for config_path in self.config_paths:
            if os.path.exists(config_path):
                for root, _, files in os.walk(config_path):
                    for file in files:
                        if file.endswith(('.conf', '.config', '.ini', '.xml')):
                            self._copy_file_with_retry(
                                os.path.join(root, file),
                                os.path.join(self.output_dir, 'config', file),
                                results
                            )
    
    def _collect_recent_files(self, results: Dict[str, Any]):
        """Collecte les fichiers récemment modifiés"""
        recent_paths = []
        if self.system == 'windows':
            recent_paths = [
                os.path.join(os.environ.get('USERPROFILE', ''), 'Recent'),
                os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows', 'Recent')
            ]
        else:
            recent_paths = [
                os.path.expanduser('~/.local/share/recently-used.xbel'),
                os.path.expanduser('~/.recently-used.xbel')
            ]
        
        for path in recent_paths:
            if os.path.exists(path):
                self._copy_file_with_retry(
                    path,
                    os.path.join(self.output_dir, 'recent', os.path.basename(path)),
                    results
                )
    
    def _collect_prefetch_files(self, results: Dict[str, Any]):
        """Collecte les fichiers prefetch (Windows uniquement)"""
        if self.prefetch_path is not None and os.path.exists(self.prefetch_path):
            for file in os.listdir(self.prefetch_path):
                if file.endswith('.pf'):
                    self._copy_file_with_retry(
                        os.path.join(self.prefetch_path, file),
                        os.path.join(self.output_dir, 'prefetch', file),
                        results
                    )
    
    def _collect_startup_files(self, results: Dict[str, Any]):
        """Collecte les fichiers de démarrage"""
        for startup_path in self.startup_paths:
            if os.path.exists(startup_path):
                for root, _, files in os.walk(startup_path):
                    for file in files:
                        self._copy_file_with_retry(
                            os.path.join(root, file),
                            os.path.join(self.output_dir, 'startup', file),
                            results
                        )
    
    def _copy_file_with_retry(self, src: str, dest: str, results: Dict[str, Any]) -> bool:
        """Copie un fichier avec des tentatives multiples en cas d'échec"""
        for attempt in range(self.max_retries):
            try:
                # Vérifier les permissions avant la copie
                if not os.access(src, os.R_OK):
                    permissions = self._get_file_permissions(src)
                    error_msg = f"Permission de lecture refusée sur {src}"
                    if permissions:
                        error_msg += f" (Propriétaire: {permissions.get('owner', 'N/A')}, " \
                                   f"Groupe: {permissions.get('group', 'N/A')}, " \
                                   f"Permissions: {permissions.get('permissions', 'N/A')})"
                    
                    self.logger.warning(error_msg)
                    results["failed"] += 1
                    results["details"]["failed"].append({
                        "source": src,
                        "error": error_msg,
                        "permissions": permissions
                    })
                    return False
                
                # Créer le dossier de destination s'il n'existe pas
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                
                # Copier le fichier
                shutil.copy2(src, dest)
                
                # Vérifier l'intégrité de la copie
                if os.path.getsize(src) != os.path.getsize(dest):
                    self.logger.warning(f"Copie incomplète de {src}")
                    results["failed"] += 1
                    results["details"]["failed"].append({
                        "source": src,
                        "error": "Copie incomplète",
                        "source_size": os.path.getsize(src),
                        "dest_size": os.path.getsize(dest)
                    })
                    return False
                
                results["collected"] += 1
                results["details"]["collected"].append({
                    "source": src,
                    "destination": dest,
                    "size": os.path.getsize(dest),
                    "hash": calculate_file_hash(dest),
                    "permissions": self._get_file_permissions(src)
                })
                return True
                
            except PermissionError as e:
                self.logger.error(f"Tentative {attempt + 1}/{self.max_retries} échouée: {str(e)}")
                if attempt == self.max_retries - 1:
                    self.logger.error(f"Échec de la copie après {self.max_retries} tentatives: {str(e)}")
                    results["failed"] += 1
                    results["details"]["failed"].append({
                        "source": src,
                        "error": str(e),
                        "permissions": self._get_file_permissions(src)
                    })
                    return False
                time.sleep(self.retry_delay)
            except Exception as e:
                self.logger.error(f"Erreur inattendue lors de la copie de {src}: {str(e)}")
                results["failed"] += 1
                results["details"]["failed"].append({
                    "source": src,
                    "error": str(e),
                    "permissions": self._get_file_permissions(src)
                })
                return False
        
        return False  # Par défaut, retourner False si toutes les tentatives échouent
    
    def _calculate_hashes(self, results: Dict[str, Any]):
        """Calcule les hashes des fichiers collectés"""
        for file_info in results["details"]["collected"]:
            try:
                file_info["hash"] = calculate_file_hash(file_info["destination"])
            except Exception as e:
                self.logger.error(f"Erreur lors du calcul du hash: {str(e)}")
                file_info["hash"] = None
    
    def collect_system_artifacts(self, investigation_id: str) -> Dict[str, Any]:
        """Collecte les artefacts système"""
        results = {
            "collected": 0,
            "failed": 0,
            "details": {
                "collected": [],
                "failed": []
            },
            "collection_time": datetime.now().isoformat(),
            "is_admin": self.is_admin
        }
        
        try:
            # Créer les répertoires de sortie
            self._create_output_dirs()
            
            # Collecter les logs système
            self._collect_logs(results)
            
            # Collecter les fichiers de configuration
            self._collect_configs(results)
            
            # Collecter les fichiers récents
            self._collect_recent_files(results)
            
            # Collecter les fichiers prefetch (Windows uniquement)
            if self.system == 'windows':
                self._collect_prefetch_files(results)
            
            # Collecter les fichiers de démarrage
            self._collect_startup_files(results)
            
            # Calculer les hashes des fichiers collectés
            self._calculate_hashes(results)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des artefacts: {str(e)}")
            results["error"] = str(e)
            return results

    def cleanup(self):
        """Nettoie les ressources utilisées par le collecteur."""
        if hasattr(self, 'logger'):
            for handler in self.logger.handlers[:]:
                self.logger.removeHandler(handler)
                handler.close()
            self.log_handler = None

def artifact_collection(investigation_id: str, output_dir: str) -> Dict[str, Any]:
    """
    Collecte les artefacts système pour l'investigation.
    
    Args:
        investigation_id: ID de l'investigation
        output_dir: Répertoire de sortie pour les artefacts
        
    Returns:
        Dict contenant les résultats de la collecte
    """
    print("[*] Collecte des artefacts en cours...")
    
    collector = ArtifactCollector(output_dir)
    results = collector.collect_system_artifacts(investigation_id)
    
    # Enregistrer les résultats
    log_event(investigation_id, "ARTIFACT_COLLECTION", results)
    
    # Afficher le résumé
    print(f"[+] Collecte terminée: {results['collected']} artefacts récupérés, {results['failed']} échecs")
    
    return results
