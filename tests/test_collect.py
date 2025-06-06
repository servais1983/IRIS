#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tests unitaires pour le module de collecte d'artefacts d'IRIS.
"""

import unittest
from unittest.mock import MagicMock, patch, mock_open
import os
import shutil
import platform
from datetime import datetime
from core.collect import ArtifactCollector, artifact_collection

class TestArtifactCollector(unittest.TestCase):
    """Tests pour le collecteur d'artefacts."""
    
    def setUp(self):
        """Configuration avant chaque test."""
        self.output_dir = "test_output"
        self.test_files_dir = "test_files"
        
        # Créer les répertoires de test
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.test_files_dir, exist_ok=True)
        
        # Créer quelques fichiers de test
        self._create_test_files()
        
        # Mock pour platform.system
        self.platform_patch = patch('platform.system')
        self.mock_platform = self.platform_patch.start()
        self.mock_platform.return_value = "Windows"
        
        # Mock pour os.environ
        self.environ_patch = patch.dict('os.environ', {
            'SystemRoot': 'C:\\Windows',
            'USERPROFILE': 'C:\\Users\\test',
            'APPDATA': 'C:\\Users\\test\\AppData\\Roaming',
            'ProgramData': 'C:\\ProgramData'
        })
        self.environ_patch.start()
        
        # Mock pour ctypes.windll.shell32.IsUserAnAdmin
        self.admin_patch = patch('ctypes.windll.shell32.IsUserAnAdmin')
        self.mock_admin = self.admin_patch.start()
        self.mock_admin.return_value = 1  # Simuler un utilisateur admin
        
        # Mock pour win32security
        self.win32security_patch = patch('core.collect.win32security')
        self.mock_win32security = self.win32security_patch.start()
        
        # Mock pour os.access
        self.access_patch = patch('os.access')
        self.mock_access = self.access_patch.start()
        self.mock_access.return_value = True
        
        # Initialiser le collecteur
        self.collector = ArtifactCollector(self.output_dir)
    
    def tearDown(self):
        """Nettoyage après chaque test."""
        # Nettoyer les ressources de NetworkContainment si instancié
        from core.contain import NetworkContainment
        for obj in list(globals().values()):
            if isinstance(obj, NetworkContainment):
                obj.cleanup()
        if hasattr(self, 'collector') and hasattr(self.collector, 'logger'):
            # Nettoyer les handlers du collecteur si besoin
            for handler in self.collector.logger.handlers[:]:
                self.collector.logger.removeHandler(handler)
                handler.close()
        # Nettoyer les répertoires de test
        def force_remove(func, path, exc):
            import stat
            os.chmod(path, stat.S_IWRITE)
            func(path)
        if os.path.exists(self.output_dir):
            try:
                for file in os.listdir(self.output_dir):
                    os.remove(os.path.join(self.output_dir, file))
                os.rmdir(self.output_dir)
            except Exception:
                pass
        if os.path.exists(self.test_files_dir):
            try:
                for file in os.listdir(self.test_files_dir):
                    os.remove(os.path.join(self.test_files_dir, file))
                os.rmdir(self.test_files_dir)
            except Exception:
                pass
        # Arrêter les mocks
        self.platform_patch.stop()
        self.environ_patch.stop()
        self.admin_patch.stop()
        self.win32security_patch.stop()
        self.access_patch.stop()
    
    def _create_test_files(self):
        """Crée des fichiers de test pour les tests."""
        # Créer un fichier log
        with open(os.path.join(self.test_files_dir, "test.log"), "w") as f:
            f.write("Test log content")
        
        # Créer un fichier de configuration
        with open(os.path.join(self.test_files_dir, "test.conf"), "w") as f:
            f.write("Test config content")
        
        # Créer un fichier prefetch
        with open(os.path.join(self.test_files_dir, "test.pf"), "w") as f:
            f.write("Test prefetch content")
    
    def test_init(self):
        """Test de l'initialisation du collecteur."""
        self.assertEqual(self.collector.output_dir, self.output_dir)
        self.assertTrue(self.collector.is_admin)
        self.assertEqual(self.collector.system, "windows")
    
    def test_is_admin(self):
        """Test de la détection des droits administrateur."""
        # Test avec un utilisateur admin
        self.mock_admin.return_value = 1
        self.assertTrue(self.collector._is_admin())
        
        # Test avec un utilisateur non-admin
        self.mock_admin.return_value = 0
        collector = ArtifactCollector(self.output_dir)
        self.assertFalse(collector._is_admin())
    
    def test_get_file_permissions(self):
        """Test de la récupération des permissions de fichiers."""
        # Mock pour GetFileSecurity
        mock_sd = MagicMock()
        self.mock_win32security.GetFileSecurity.return_value = mock_sd
        
        # Mock pour les SIDs
        mock_owner_sid = MagicMock()
        mock_group_sid = MagicMock()
        mock_sd.GetSecurityDescriptorOwner.return_value = mock_owner_sid
        mock_sd.GetSecurityDescriptorGroup.return_value = mock_group_sid
        
        # Mock pour LookupAccountSid
        self.mock_win32security.LookupAccountSid.return_value = ("test_user", "test_domain", 1, 1)
        
        # Test avec un fichier Windows
        permissions = self.collector._get_file_permissions("test.txt")
        self.assertEqual(permissions["owner"], "test_user")
        self.assertEqual(permissions["group"], "test_user")
        self.assertEqual(permissions["permissions"], "Windows ACL")
    
    def test_create_output_dirs(self):
        """Test de la création des répertoires de sortie."""
        self.collector._create_output_dirs()
        for dir_name in ['logs', 'config', 'recent', 'prefetch', 'startup']:
            dir_path = os.path.join(self.output_dir, dir_name)
            self.assertTrue(os.path.exists(dir_path))
            self.assertTrue(os.path.isdir(dir_path))
    
    def test_copy_file_with_retry(self):
        """Test de la copie de fichiers avec tentatives multiples."""
        src = os.path.join(self.test_files_dir, "test.log")
        dest = os.path.join(self.output_dir, "test.log")
        self.mock_access.return_value = True
        # Test avec succès
        result = {
            "success": 0,
            "failed": 0,
            "details": {
                "collected": [],
                "failed": []
            },
            "collected": 0
        }
        success = self.collector._copy_file_with_retry(src, dest, result)
        self.assertTrue(success)
        self.assertEqual(result["collected"], 1)
        self.assertTrue(os.path.exists(dest))
        # Test avec échec de permission
        self.mock_access.return_value = False
        result = {
            "success": 0,
            "failed": 0,
            "details": {
                "collected": [],
                "failed": []
            },
            "collected": 0
        }
        success = self.collector._copy_file_with_retry(src, dest, result)
        self.assertFalse(success)
        self.assertEqual(result["failed"], 1)
    
    def test_collect_system_artifacts(self):
        """Test de la collecte d'artefacts système."""
        # Mock pour les méthodes de collecte
        with patch.object(self.collector, '_collect_logs') as mock_logs, \
             patch.object(self.collector, '_collect_configs') as mock_configs, \
             patch.object(self.collector, '_collect_recent_files') as mock_recent, \
             patch.object(self.collector, '_collect_prefetch_files') as mock_prefetch, \
             patch.object(self.collector, '_collect_startup_files') as mock_startup, \
             patch.object(self.collector, '_calculate_hashes') as mock_hashes:
            # On simule un résultat minimal
            mock_logs.return_value = None
            mock_configs.return_value = None
            mock_recent.return_value = None
            mock_prefetch.return_value = None
            mock_startup.return_value = None
            mock_hashes.return_value = None
            result = self.collector.collect_system_artifacts("test_investigation")
            # Vérifier la structure du résultat
            self.assertIn("collected", result)
            self.assertIn("failed", result)
            self.assertIn("details", result)
            self.assertIn("collection_time", result)
            self.assertIn("is_admin", result)
    
    def test_artifact_collection(self):
        """Test de la fonction de collecte d'artefacts."""
        with patch('core.collect.ArtifactCollector') as mock_collector:
            mock_instance = mock_collector.return_value
            mock_instance.collect_system_artifacts.return_value = {
                "investigation_id": "test_investigation",
                "timestamp": datetime.now().isoformat(),
                "system_info": {"os": "Windows"},
                "artifacts": [],
                "success": 0,
                "failed": 0,
                "collected": 0
            }
            result = artifact_collection("test_investigation", self.output_dir)
            mock_collector.assert_called_once_with(self.output_dir)
            mock_instance.collect_system_artifacts.assert_called_once_with("test_investigation")
            self.assertEqual(result["investigation_id"], "test_investigation")
            self.assertIn("timestamp", result)
            self.assertEqual(result["system_info"]["os"], "Windows")

if __name__ == '__main__':
    unittest.main() 