#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de surveillance en temps réel.
"""

import time
import threading
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from dataclasses import dataclass

@dataclass
class SecurityEvent:
    """Représente un événement de sécurité."""
    timestamp: datetime
    event_type: str
    severity: str
    description: str
    details: Dict[str, Any]

class SecurityMonitor:
    """Surveillance en temps réel des événements de sécurité."""
    
    def __init__(self, analyzer):
        """Initialise le moniteur de sécurité.
        
        Args:
            analyzer: Instance de MemoryAnalyzer pour l'analyse
        """
        self.analyzer = analyzer
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.logger = logging.getLogger(__name__)
        self.events: List[SecurityEvent] = []
        
    def start(self, interval: int = 60):
        """Démarre la surveillance en temps réel.
        
        Args:
            interval: Intervalle de vérification en secondes
        """
        if self.running:
            return
            
        self.running = True
        self.thread = threading.Thread(
            target=self._monitor_loop,
            args=(interval,),
            daemon=True
        )
        self.thread.start()
        self.logger.info(f"Surveillance démarrée (intervalle: {interval}s)")
        
    def stop(self):
        """Arrête la surveillance."""
        self.running = False
        if self.thread:
            self.thread.join()
        self.logger.info("Surveillance arrêtée")
        
    def _monitor_loop(self, interval: int):
        """Boucle principale de surveillance.
        
        Args:
            interval: Intervalle de vérification en secondes
        """
        while self.running:
            try:
                # Vérifier les processus
                suspicious_processes = self.analyzer.analyze_processes()
                for proc in suspicious_processes:
                    self._handle_suspicious_process(proc)
                
                # Vérifier le réseau
                network_results = self.analyzer.analyze_network()
                for conn in network_results:
                    self._handle_suspicious_connection(conn)
                
                # Vérifier les privilèges
                for proc in self.analyzer.get_running_processes():
                    if self.analyzer._has_elevated_privileges(proc):
                        self._handle_elevated_privileges(proc)
                
            except Exception as e:
                self.logger.error(f"Erreur dans la boucle de surveillance: {str(e)}")
            
            time.sleep(interval)
            
    def _handle_suspicious_process(self, process):
        """Gère un processus suspect.
        
        Args:
            process: Processus suspect détecté
        """
        event = SecurityEvent(
            timestamp=datetime.now(),
            event_type="suspicious_process",
            severity="high",
            description=f"Processus suspect détecté: {process.name}",
            details={
                "pid": process.pid,
                "name": process.name,
                "reasons": process.suspicious_reasons
            }
        )
        self.events.append(event)
        self.logger.warning(f"Processus suspect: {process.name} (PID: {process.pid})")
        
    def _handle_suspicious_connection(self, connection):
        """Gère une connexion suspecte.
        
        Args:
            connection: Connexion suspecte détectée
        """
        event = SecurityEvent(
            timestamp=datetime.now(),
            event_type="suspicious_connection",
            severity="medium",
            description=f"Connexion suspecte détectée: {connection.process_name}",
            details={
                "process": connection.process_name,
                "local_port": connection.local_port,
                "remote_addr": connection.remote_addr,
                "remote_port": connection.remote_port
            }
        )
        self.events.append(event)
        self.logger.warning(
            f"Connexion suspecte: {connection.process_name} -> "
            f"{connection.remote_addr}:{connection.remote_port}"
        )
        
    def _handle_elevated_privileges(self, process):
        """Gère un processus avec privilèges élevés.
        
        Args:
            process: Processus avec privilèges élevés
        """
        event = SecurityEvent(
            timestamp=datetime.now(),
            event_type="elevated_privileges",
            severity="high",
            description=f"Processus avec privilèges élevés: {process.name}",
            details={
                "pid": process.pid,
                "name": process.name,
                "username": process.username
            }
        )
        self.events.append(event)
        self.logger.warning(f"Privilèges élevés: {process.name} (PID: {process.pid})")
        
    def get_recent_events(self, minutes: int = 5) -> List[SecurityEvent]:
        """Récupère les événements récents.
        
        Args:
            minutes: Nombre de minutes à remonter
            
        Returns:
            Liste des événements récents
        """
        cutoff = datetime.now() - timedelta(minutes=minutes)
        return [e for e in self.events if e.timestamp > cutoff] 