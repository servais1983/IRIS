#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tests unitaires pour le module de génération de rapports d'IRIS.
"""

import unittest
from unittest.mock import patch, mock_open, MagicMock
import os
import json
import datetime
import matplotlib.pyplot as plt
from core.report import generate_report

class TestReportGeneration(unittest.TestCase):
    """Tests pour la génération de rapports."""
    
    def setUp(self):
        """Configuration initiale pour chaque test."""
        self.session_id = "test_session_123"
        self.test_events = [
            {
                "type": "INVESTIGATION_START",
                "timestamp": "2024-03-20T10:00:00Z",
                "data": {"mode": "full"}
            },
            {
                "type": "MEMORY_ANALYSIS",
                "timestamp": "2024-03-20T10:01:00Z",
                "data": {
                    "total_processes": 100,
                    "suspicious_processes": 2,
                    "details": [
                        {
                            "pid": 1234,
                            "name": "suspicious.exe",
                            "username": "user1",
                            "suspicious": True
                        },
                        {
                            "pid": 5678,
                            "name": "malware.exe",
                            "username": "user2",
                            "suspicious": True
                        }
                    ]
                }
            },
            {
                "type": "ARTIFACT_COLLECTION_SUMMARY",
                "timestamp": "2024-03-20T10:02:00Z",
                "data": {
                    "collected": 50,
                    "failed": 2,
                    "system": "Windows"
                }
            },
            {
                "type": "NETWORK_CONTAINMENT",
                "timestamp": "2024-03-20T10:03:00Z",
                "data": {
                    "blocked_ips": ["192.168.1.1", "10.0.0.1"],
                    "failed_ips": ["172.16.0.1"]
                }
            },
            {
                "type": "THREAT_INTEL",
                "timestamp": "2024-03-20T10:04:00Z",
                "data": {
                    "malicious.com": {
                        "VirusTotal": {
                            "found": True,
                            "positives": 5,
                            "total": 70
                        },
                        "AlienVault OTX": {
                            "found": True,
                            "pulse_count": 2
                        }
                    }
                }
            },
            {
                "type": "INVESTIGATION_END",
                "timestamp": "2024-03-20T10:05:00Z",
                "data": {}
            }
        ]
        
        # Mock pour matplotlib
        self.plt_patch = patch('matplotlib.pyplot')
        self.mock_plt = self.plt_patch.start()
        self.mock_plt.figure.return_value = MagicMock()
        self.mock_plt.gca.return_value = MagicMock()
        
    def tearDown(self):
        """Nettoyage après chaque test."""
        self.plt_patch.stop()
    
    def _mock_log_file(self, events):
        # Génère un contenu de fichier où chaque ligne est un événement JSON
        lines = [json.dumps(ev) + '\n' for ev in events]
        m = mock_open(read_data=''.join(lines))
        m.return_value.__iter__.return_value = lines
        return m

    @patch('os.path.exists')
    def test_generate_report_success(self, mock_exists):
        mock_exists.return_value = True
        m = self._mock_log_file(self.test_events)
        with patch('builtins.open', m):
            result = generate_report(self.session_id)
        self.assertTrue(result)

    @patch('os.path.exists')
    def test_generate_report_quick(self, mock_exists):
        mock_exists.return_value = True
        m = self._mock_log_file(self.test_events)
        with patch('builtins.open', m):
            result = generate_report(self.session_id, quick=True)
        self.assertTrue(result)

    @patch('os.path.exists')
    def test_generate_report_missing_log(self, mock_exists):
        mock_exists.return_value = False
        result = generate_report("nonexistent_session")
        self.assertFalse(result)

    @patch('os.path.exists')
    def test_generate_report_empty_log(self, mock_exists):
        mock_exists.return_value = True
        m = mock_open(read_data='')
        m.return_value.__iter__.return_value = []
        with patch('builtins.open', m):
            result = generate_report(self.session_id)
        self.assertFalse(result)

    @patch('os.path.exists')
    def test_generate_report_invalid_json(self, mock_exists):
        mock_exists.return_value = True
        # Simule une ligne JSON invalide
        m = mock_open(read_data='not_a_json\n')
        m.return_value.__iter__.return_value = ['not_a_json\n']
        with patch('builtins.open', m):
            result = generate_report(self.session_id)
        self.assertFalse(result)

    @patch('os.path.exists')
    def test_generate_report_timeline_error(self, mock_exists):
        mock_exists.return_value = True
        m = self._mock_log_file(self.test_events)
        self.mock_plt.savefig.side_effect = Exception("Timeline error")
        with patch('builtins.open', m):
            result = generate_report(self.session_id)
        self.assertTrue(result)

    @patch('os.path.exists')
    def test_generate_report_with_missing_events(self, mock_exists):
        mock_exists.return_value = True
        minimal_events = [
            {
                "type": "INVESTIGATION_START",
                "timestamp": "2024-03-20T10:00:00Z",
                "data": {"mode": "full"}
            },
            {
                "type": "INVESTIGATION_END",
                "timestamp": "2024-03-20T10:05:00Z",
                "data": {}
            }
        ]
        m = self._mock_log_file(minimal_events)
        with patch('builtins.open', m):
            result = generate_report(self.session_id)
        self.assertTrue(result)  # Un rapport minimal est généré même avec des événements minimaux

if __name__ == '__main__':
    unittest.main() 