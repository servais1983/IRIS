#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tests unitaires pour le module d'analyse mémoire d'IRIS.
"""

import unittest
from unittest.mock import MagicMock, patch, mock_open
import os
import json
from datetime import datetime
import psutil
import shutil
import sys
import logging
from core.analyze import MemoryAnalyzer, memory_forensics, ProcessCategory, ProcessInfo
from core.analyze import MemoryAnalyzerError, ProcessAccessError, NetworkAnalysisError, ConfigurationError
from pathlib import Path
from collections import namedtuple

# Ajouter le répertoire parent au PYTHONPATH
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class TestMemoryAnalyzer(unittest.TestCase):
    """Tests pour la classe MemoryAnalyzer."""
    
    def setUp(self):
        """Configuration initiale pour les tests."""
        self.test_output_dir = os.path.join(os.path.dirname(__file__), "test_output")
        os.makedirs(self.test_output_dir, exist_ok=True)
        
        # Configuration du logger pour les tests
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        
        # Mock pour les processus
        self.mock_process = MagicMock()
        self.mock_process.pid = 1234
        self.mock_process.name.return_value = "test_process"
        self.mock_process.username.return_value = "test_user"
        self.mock_process.memory_percent.return_value = 10.0
        self.mock_process.cpu_percent.return_value = 5.0
        self.mock_process.create_time.return_value = datetime.now().timestamp()
        self.mock_process.cmdline.return_value = ["test_process"]
        
        # Mock pour les connexions réseau
        self.mock_connection = MagicMock()
        self.mock_connection.laddr = ("127.0.0.1", 80)
        self.mock_connection.raddr = ("192.168.1.1", 443)
        self.mock_connection.status = "ESTABLISHED"
        self.mock_connection.pid = 1234
        
        # Initialisation de l'analyseur
        self.analyzer = MemoryAnalyzer(self.test_output_dir)
        
    def tearDown(self):
        """Nettoyage après les tests."""
        # Fermer tous les handlers du logger
        for handler in self.analyzer.logger.handlers[:]:
            handler.close()
            self.analyzer.logger.removeHandler(handler)
            
        if os.path.exists(self.test_output_dir):
            try:
                for file in os.listdir(self.test_output_dir):
                    file_path = os.path.join(self.test_output_dir, file)
                    try:
                        if os.path.isfile(file_path):
                            os.chmod(file_path, 0o777)
                            os.remove(file_path)
                        elif os.path.isdir(file_path):
                            os.chmod(file_path, 0o777)
                            os.rmdir(file_path)
                    except Exception as e:
                        print(f"Impossible de supprimer {file_path}: {str(e)}")
                os.rmdir(self.test_output_dir)
            except Exception as e:
                print(f"Erreur lors du nettoyage: {str(e)}")
    
    def test_init_valid(self):
        """Test l'initialisation avec un répertoire de sortie valide."""
        self.assertEqual(str(self.analyzer.output_dir), self.test_output_dir)
        self.assertIsNotNone(self.analyzer.logger)
    
    def test_init_invalid_output_dir(self):
        """Test l'initialisation avec un répertoire de sortie invalide."""
        with self.assertRaises(ConfigurationError):
            MemoryAnalyzer("__chemin_inexistant_12345__")
    
    def test_init_unsupported_os(self):
        """Test l'initialisation sur un système d'exploitation non supporté."""
        with patch('platform.system', return_value="UnsupportedOS"):
            with self.assertRaises(ConfigurationError):
                MemoryAnalyzer(self.test_output_dir)
    
    def test_load_whitelist(self):
        """Test le chargement de la liste blanche."""
        test_whitelist = {
            "windows": {
                "SYSTEM": ["svchost.exe", "System"],
                "USER": ["explorer.exe", "chrome.exe"],
                "SERVICE": ["spoolsv.exe", "winlogon.exe"]
            },
            "linux": {
                "SYSTEM": ["systemd", "init"],
                "USER": ["bash", "firefox"],
                "SERVICE": ["sshd", "apache2"]
            }
        }
        with patch('builtins.open', mock_open(read_data=json.dumps(test_whitelist))):
            self.analyzer._load_whitelist()
            self.assertEqual(self.analyzer.whitelist, test_whitelist)
    
    def test_is_whitelisted_process(self):
        """Test la vérification des processus dans la liste blanche."""
        self.analyzer.whitelist = {
            "windows": {
                "SYSTEM": ["svchost.exe"],
                "USER": ["explorer.exe"],
                "SERVICE": ["spoolsv.exe"]
            }
        }
        self.assertTrue(self.analyzer._is_whitelisted("svchost.exe"))
    
    def test_is_whitelisted_port(self):
        """Test la vérification des ports dans la liste blanche."""
        self.analyzer.whitelist = {
            "ports": [80, 443, 8080]
        }
        self.assertTrue(self.analyzer._is_whitelisted_port(80))
    
    def test_is_whitelisted_ip(self):
        """Test la vérification des IPs dans la liste blanche."""
        self.analyzer.whitelist = {
            "ips": ["192.168.1.1", "10.0.0.1"]
        }
        self.assertTrue(self.analyzer._is_whitelisted_ip("192.168.1.1"))
    
    def test_is_known_good_process(self):
        """Test la détection des processus connus comme sûrs."""
        self.analyzer.whitelist = {
            "windows": {
                ProcessCategory.SYSTEM: ["svchost.exe"]
            }
        }
        self.assertTrue(self.analyzer._is_known_good_process("svchost.exe"))
    
    def test_is_suspicious_name(self):
        """Test la détection des noms de processus suspects."""
        suspicious_names = ["malware.exe", "backdoor.exe", "trojan.exe"]
        for name in suspicious_names:
            self.assertTrue(self.analyzer._is_suspicious_name(name))
    
    def test_is_recently_created(self):
        """Test la détection des processus récemment créés."""
        now = datetime.now()
        self.mock_process.create_time.return_value = now.timestamp()
        self.assertTrue(self.analyzer._is_recently_created(self.mock_process))
    
    def test_has_elevated_privileges(self):
        """Test la détection des privilèges élevés."""
        with patch.object(self.mock_process, 'username', return_value="SYSTEM"):
            self.assertTrue(self.analyzer._has_elevated_privileges(self.mock_process))
    
    def test_is_suspicious_cmdline(self):
        """Test la détection des lignes de commande suspectes."""
        suspicious_cmdlines = [
            ["python", "-c", "import os; os.system('rm -rf /')"],
            ["powershell", "-enc", "base64_encoded_malware"],
            ["cmd", "/c", "net user hacker /add"]
        ]
        
        for cmdline in suspicious_cmdlines:
            self.assertTrue(self.analyzer._is_suspicious_cmdline(cmdline))
    
    def test_is_unusual_parent(self):
        """Test la détection des processus parents inhabituels."""
        # Mock pour un processus parent normal
        normal_parent = MagicMock()
        normal_parent.name.return_value = "explorer.exe"
        self.assertFalse(self.analyzer._is_unusual_parent(normal_parent))
        
        # Mock pour un processus parent suspect
        suspicious_parent = MagicMock()
        suspicious_parent.name.return_value = "unknown_process.exe"
        self.assertTrue(self.analyzer._is_unusual_parent(suspicious_parent))
    
    def test_has_suspicious_network_activity(self):
        """Test la détection des activités réseau suspectes."""
        from collections import namedtuple
        Addr = namedtuple('Addr', ['ip', 'port'])
        # Mock pour des connexions normales
        normal_connections = [
            MagicMock(laddr=Addr("127.0.0.1", 80), raddr=Addr("192.168.1.1", 443)),
            MagicMock(laddr=Addr("127.0.0.1", 8080), raddr=Addr("192.168.1.2", 80))
        ]
        with patch.object(self.mock_process, 'connections', return_value=normal_connections):
            self.assertFalse(self.analyzer._has_suspicious_network_activity(self.mock_process))
        
        # Mock pour des connexions suspectes
        suspicious_connections = [
            MagicMock(laddr=Addr("127.0.0.1", 4444), raddr=Addr("1.2.3.4", 1337)),
            MagicMock(laddr=Addr("127.0.0.1", 8080), raddr=Addr("5.6.7.8", 31337))
        ]
        with patch.object(self.mock_process, 'connections', return_value=suspicious_connections):
            self.assertTrue(self.analyzer._has_suspicious_network_activity(self.mock_process))
    
    def test_analyze_processes(self):
        """Test l'analyse complète des processus."""
        # Mock pour la liste des processus
        processes = [self.mock_process]
        with patch('psutil.process_iter', return_value=processes):
            with patch.object(self.analyzer, '_is_suspicious_process', return_value=True):
                results = self.analyzer.analyze_processes()
                self.assertEqual(len(results), 1)
    
    def test_analyze_network(self):
        """Test l'analyse complète du réseau."""
        # Mock pour les connexions réseau
        connections = [self.mock_connection]
        with patch('psutil.net_connections', return_value=connections):
            results = self.analyzer.analyze_network()
            self.assertIsNotNone(results)
    
    def test_save_results(self):
        """Test la sauvegarde des résultats."""
        test_results = {
            "processes": [
                ProcessInfo(
                    pid=1234,
                    name="test_process",
                    username="test_user",
                    memory_percent=10.0,
                    cpu_percent=5.0,
                    create_time=datetime.now(),
                    cmdline=["test_process"],
                    is_suspicious=True,
                    suspicious_reasons=["Test reason"]
                )
            ]
        }
        
        self.analyzer.save_results(test_results)
        output_file = os.path.join(self.test_output_dir, "analysis_results.json")
        self.assertTrue(os.path.exists(output_file))
    
    def test_error_handling(self):
        """Test la gestion des erreurs."""
        # Test ProcessAccessError
        with patch.object(self.mock_process, 'cpu_percent', side_effect=psutil.AccessDenied):
            with self.assertRaises(ProcessAccessError):
                self.analyzer._get_process_info(self.mock_process)

if __name__ == '__main__':
    unittest.main() 