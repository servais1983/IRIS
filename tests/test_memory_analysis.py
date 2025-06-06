import unittest
import os
import tempfile
import psutil
from core.analyze import MemoryAnalyzer
import logging
import json
from datetime import datetime
from unittest.mock import patch, MagicMock
import shutil
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class TestMemoryAnalyzer(unittest.TestCase):
    def setUp(self):
        self.test_dir = 'test_output'
        os.makedirs(self.test_dir, exist_ok=True)
        self.analyzer = MemoryAnalyzer(output_dir=self.test_dir)
        self.test_process = {
            'pid': 1234,
            'name': 'test.exe',
            'username': 'test_user',
            'cmdline': ['test.exe', '--arg'],
            'cpu_percent': 10.0,
            'memory_percent': 5.0,
            'create_time': datetime.now().timestamp()
        }
    
    def tearDown(self):
        # Nettoyer les ressources
        if hasattr(self, 'analyzer'):
            self.analyzer.cleanup()
        
        # Nettoyer les fichiers temporaires
        if os.path.exists(self.test_dir):
            try:
                shutil.rmtree(self.test_dir)
            except PermissionError:
                # Ignorer les erreurs de permission lors du nettoyage
                pass
    
    def test_analyze_processes(self):
        with patch('psutil.process_iter') as mock_process_iter:
            mock_process = MagicMock()
            mock_process.info = self.test_process
            mock_process.cpu_percent.return_value = 10
            mock_process.memory_percent.return_value = 5
            mock_process_iter.return_value = [mock_process]
            
            result = self.analyzer.analyze_processes()
            self.assertIsInstance(result, dict)
            self.assertIn('total_processes', result)
            self.assertIn('suspicious_processes', result)
            self.assertIn('analysis_time', result)
    
    def test_analyze_memory_usage(self):
        """Test de l'analyse de l'utilisation de la mémoire"""
        with patch('psutil.virtual_memory') as mock_vm, \
             patch('psutil.swap_memory') as mock_swap:
            mock_vm.return_value = MagicMock(
                total=8 * 1024 * 1024 * 1024,
                available=4 * 1024 * 1024 * 1024,
                percent=50
            )
            mock_swap.return_value = MagicMock(
                total=30 * 1024 * 1024 * 1024,
                used=3.5 * 1024 * 1024 * 1024,
                percent=12.5
            )
            
            result = self.analyzer.analyze_memory_usage()
            self.assertIsInstance(result, dict)
            self.assertIn('total_memory', result)
            self.assertEqual(result['total_memory'], 8 * 1024 * 1024 * 1024)
            self.assertEqual(result['available_memory'], 4 * 1024 * 1024 * 1024)
            self.assertEqual(result['memory_percent'], 50)
            self.assertEqual(result['swap_total'], 30 * 1024 * 1024 * 1024)
            self.assertEqual(result['swap_used'], 3.5 * 1024 * 1024 * 1024)
            self.assertEqual(result['swap_percent'], 12.5)
    
    def test_analyze_network_connections(self):
        with patch('psutil.net_connections') as mock_connections:
            mock_conn = MagicMock()
            mock_conn.laddr = ('127.0.0.1', 8080)
            mock_conn.raddr = ('192.168.1.1', 80)
            mock_conn.status = 'ESTABLISHED'
            mock_conn.pid = 1234
            mock_connections.return_value = [mock_conn]
            
            result = self.analyzer.analyze_network_connections()
            self.assertIsInstance(result, dict)
            self.assertIn('total_connections', result)
            self.assertIn('suspicious_connections', result)
            self.assertIn('analysis_time', result)
    
    def test_is_suspicious_process(self):
        suspicious_process = {
            'name': 'malicious.exe',
            'cmdline': ['malicious.exe', '--malicious'],
            'cpu_percent': 90.0,
            'memory_percent': 80.0
        }
        mock_process = MagicMock()
        mock_process.info = suspicious_process
        mock_process.cpu_percent.return_value = 90.0
        mock_process.memory_percent.return_value = 80.0
        self.assertTrue(self.analyzer._is_suspicious_process(mock_process))
    
    def test_is_whitelisted(self):
        whitelisted_process = {
            'name': 'svchost.exe',
            'cmdline': ['svchost.exe', '-k', 'NetworkService']
        }
        mock_process = MagicMock()
        mock_process.name.return_value = 'svchost.exe'
        mock_process.cmdline.return_value = ['svchost.exe', '-k', 'NetworkService']
        self.assertTrue(self.analyzer._is_whitelisted(mock_process))
    
    def test_suspicious_name_detection(self):
        suspicious_names = ['malware.exe', 'trojan.exe', 'backdoor.exe']
        for name in suspicious_names:
            self.assertTrue(self.analyzer._is_suspicious_name(name))
    
    def test_suspicious_cmdline_detection(self):
        suspicious_cmdlines = [
            ['malicious.exe', '--encrypt'],
            ['trojan.exe', '--connect', 'evil.com'],
            ['backdoor.exe', '--listen', '4444']
        ]
        for cmdline in suspicious_cmdlines:
            self.assertTrue(self.analyzer._is_suspicious_cmdline(cmdline))
    
    def test_logging_setup(self):
        self.assertIsNotNone(self.analyzer.logger)
        self.assertEqual(len(self.analyzer.logger.handlers), 1)
    
    def test_memory_forensics(self):
        with patch('psutil.process_iter') as mock_process_iter, \
             patch('psutil.virtual_memory') as mock_vm, \
             patch('psutil.swap_memory') as mock_swap, \
             patch('psutil.net_connections') as mock_connections:
            
            # Mock process
            mock_process = MagicMock()
            mock_process.info = self.test_process
            mock_process.cpu_percent.return_value = 10
            mock_process.memory_percent.return_value = 5
            mock_process.name.return_value = 'test.exe'
            mock_process.cmdline.return_value = ['test.exe', '--arg']
            mock_process_iter.return_value = [mock_process]
            
            # Mock memory
            mock_vm.return_value = MagicMock(
                total=8 * 1024 * 1024 * 1024,
                available=4 * 1024 * 1024 * 1024,
                percent=50
            )
            mock_swap.return_value = MagicMock(
                total=30 * 1024 * 1024 * 1024,
                used=3.5 * 1024 * 1024 * 1024,
                percent=12.5
            )
            
            # Mock network
            mock_conn = MagicMock()
            mock_conn.laddr = ('127.0.0.1', 8080)
            mock_conn.raddr = ('192.168.1.1', 80)
            mock_conn.status = 'ESTABLISHED'
            mock_conn.pid = 1234
            mock_connections.return_value = [mock_conn]
            
            result = self.analyzer.analyze_memory_usage()
            self.assertIsInstance(result, dict)
            self.assertIn('total_memory', result)
            self.assertIn('available_memory', result)
            self.assertIn('memory_percent', result)
            self.assertIn('swap_total', result)
            self.assertIn('swap_used', result)
            self.assertIn('swap_percent', result)
    
    def test_invalid_output_dir(self):
        """Test avec un dossier de sortie invalide"""
        with self.assertRaises(ValueError):
            MemoryAnalyzer("")
    
    def test_unsupported_os(self):
        """Test avec un système d'exploitation non supporté"""
        with patch('platform.system', return_value='unsupported'):
            with self.assertRaises(NotImplementedError):
                MemoryAnalyzer(self.test_dir)

if __name__ == '__main__':
    unittest.main() 