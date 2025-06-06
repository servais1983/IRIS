#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tests unitaires pour le module de containment réseau d'IRIS.
"""

import unittest
from unittest.mock import patch, MagicMock
import os
import platform
import subprocess
from datetime import datetime
from core.contain import NetworkContainment, network_containment

class TestNetworkContainment(unittest.TestCase):
    """Tests pour le module de containment réseau."""
    
    def setUp(self):
        """Configuration avant chaque test."""
        self.output_dir = "test_output"
        self.test_ips = ["192.168.1.1", "10.0.0.1"]
        self.investigation_id = "test_investigation"
        
        # Créer le répertoire de sortie
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Patches pour les dépendances
        self.platform_patch = patch('platform.system')
        self.subprocess_patch = patch('subprocess.run')
        self.log_event_patch = patch('core.utils.log_event')
        self.os_path_patch = patch('os.path.exists')
        
        # Démarrer les mocks
        self.mock_platform = self.platform_patch.start()
        self.mock_subprocess = self.subprocess_patch.start()
        self.mock_log_event = self.log_event_patch.start()
        self.mock_os_path = self.os_path_patch.start()
        
        # Configurer le mock platform
        self.mock_platform.return_value = "Windows"
        
        # Configurer le mock os.path.exists
        self.mock_os_path.return_value = True
        
        # Configurer le mock subprocess avec side_effect
        def subprocess_side_effect(*args, **kwargs):
            cmd = args[0]
            if isinstance(cmd, list):
                cmd = ' '.join(cmd)
            
            mock_result = MagicMock()
            if 'id -u' in cmd:
                mock_result.stdout = "0"
                mock_result.returncode = 0
            elif 'netsh' in cmd or 'ifconfig' in cmd:
                mock_result.returncode = 0
            else:
                mock_result.returncode = 0
            return mock_result
            
        self.mock_subprocess.side_effect = subprocess_side_effect
        
        # Initialiser l'objet de test
        self.containment = NetworkContainment(self.output_dir)
    
    def tearDown(self):
        """Nettoyage après chaque test."""
        # Arrêter les mocks
        self.platform_patch.stop()
        self.subprocess_patch.stop()
        self.log_event_patch.stop()
        self.os_path_patch.stop()
        
        # Nettoyer les ressources de l'objet containment
        if hasattr(self, 'containment'):
            self.containment.cleanup()
        
        # Nettoyer les fichiers créés
        if os.path.exists(self.output_dir):
            try:
                for file in os.listdir(self.output_dir):
                    os.remove(os.path.join(self.output_dir, file))
                os.rmdir(self.output_dir)
            except Exception:
                pass
    
    def test_init_windows(self):
        """Test de l'initialisation sous Windows."""
        self.assertEqual(self.containment.system, "windows")
        self.assertTrue(os.path.exists(self.output_dir))
    
    def test_init_linux(self):
        """Test de l'initialisation sous Linux."""
        self.mock_platform.return_value = "Linux"
        containment = NetworkContainment(self.output_dir)
        self.assertEqual(containment.system, "linux")
    
    def test_is_admin_windows(self):
        """Test de la vérification des droits admin sous Windows."""
        # Test avec droits admin
        self.mock_subprocess.side_effect = lambda *args, **kwargs: MagicMock(returncode=0)
        self.assertTrue(self.containment._is_admin())
        
        # Test sans droits admin
        self.mock_subprocess.side_effect = lambda *args, **kwargs: MagicMock(returncode=1)
        self.assertFalse(self.containment._is_admin())
    
    def test_is_admin_linux(self):
        """Test de la vérification des droits admin sous Linux."""
        self.mock_platform.return_value = "Linux"
        containment = NetworkContainment(self.output_dir)
        
        # Test avec droits root
        self.mock_subprocess.side_effect = lambda *args, **kwargs: MagicMock(stdout="0", returncode=0)
        self.assertTrue(containment._is_admin())
        
        # Test sans droits root
        self.mock_subprocess.side_effect = lambda *args, **kwargs: MagicMock(stdout="1000", returncode=0)
        self.assertFalse(containment._is_admin())
    
    def test_block_ips_windows(self):
        """Test du blocage d'IPs sous Windows."""
        results = self.containment.block_ips(self.test_ips, self.investigation_id)
        
        self.assertEqual(len(results["blocked"]), 2)
        self.assertEqual(len(results["failed"]), 0)
        self.assertIn("block_time", results)
    
    def test_block_ips_linux(self):
        """Test du blocage d'IPs sous Linux."""
        self.mock_platform.return_value = "Linux"
        containment = NetworkContainment(self.output_dir)
        
        results = containment.block_ips(self.test_ips, self.investigation_id)
        
        self.assertEqual(len(results["blocked"]), 2)
        self.assertEqual(len(results["failed"]), 0)
        self.assertIn("block_time", results)
    
    def test_block_ips_failure(self):
        """Test du blocage d'IPs avec échec."""
        self.mock_subprocess.side_effect = subprocess.CalledProcessError(1, "cmd")
        
        results = self.containment.block_ips(self.test_ips, self.investigation_id)
        
        self.assertEqual(len(results["blocked"]), 0)
        self.assertEqual(len(results["failed"]), 2)
    
    def test_unblock_ips(self):
        """Test du déblocage d'IPs."""
        # D'abord bloquer les IPs
        self.containment.block_ips(self.test_ips, self.investigation_id)
        
        # Puis les débloquer
        results = self.containment.unblock_ips(self.test_ips)
        
        self.assertEqual(len(results["unblocked"]), 2)
        self.assertEqual(len(results["failed"]), 0)
        self.assertIn("unblock_time", results)
    
    def test_isolate_system_windows(self):
        """Test de l'isolation système sous Windows."""
        result = self.containment.isolate_system("test_system")
        self.assertTrue(result)
        self.mock_subprocess.assert_called()
    
    def test_isolate_system_linux(self):
        """Test de l'isolation système sous Linux."""
        self.mock_platform.return_value = "Linux"
        containment = NetworkContainment(self.output_dir)
        
        result = containment.isolate_system("test_system")
        self.assertTrue(result)
        self.mock_subprocess.assert_called()
    
    def test_restore_network_windows(self):
        """Test de la restauration réseau sous Windows."""
        result = self.containment.restore_network()
        self.assertTrue(result)
        self.mock_subprocess.assert_called()
    
    def test_restore_network_linux(self):
        """Test de la restauration réseau sous Linux."""
        self.mock_platform.return_value = "Linux"
        containment = NetworkContainment(self.output_dir)
        
        result = containment.restore_network()
        self.assertTrue(result)
        self.mock_subprocess.assert_called()
    
    def test_network_containment_function(self):
        """Test de la fonction network_containment."""
        # Configurer le mock pour simuler les droits admin
        def subprocess_side_effect(*args, **kwargs):
            cmd = args[0]
            if isinstance(cmd, list):
                cmd = ' '.join(cmd)
            
            mock_result = MagicMock()
            if 'id -u' in cmd:
                mock_result.stdout = "0"
                mock_result.returncode = 0
            elif 'netsh' in cmd or 'ifconfig' in cmd:
                mock_result.returncode = 0
            else:
                mock_result.returncode = 0
            return mock_result
            
        self.mock_subprocess.side_effect = subprocess_side_effect
        
        # Utiliser un patch contextuel pour log_event
        with patch('core.contain.log_event') as mock_log:
            results = network_containment(
                self.investigation_id,
                self.test_ips,
                "test_system"
            )
            
            self.assertIn("blocked_ips", results)
            self.assertIn("failed_ips", results)
            self.assertIn("system_isolated", results)
            
            # Vérifier que le dernier appel à log_event est correct
            expected_call = (
                self.investigation_id,
                "NETWORK_CONTAINMENT",
                {
                    "blocked_ips": self.test_ips,
                    "failed_ips": [],
                    "system_isolated": True
                }
            )
            self.assertEqual(mock_log.call_args_list[-1][0], expected_call)

if __name__ == '__main__':
    unittest.main() 