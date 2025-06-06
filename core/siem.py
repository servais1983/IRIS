"""
Module d'intégration avec les systèmes SIEM.
"""

import json
import logging
import requests
from typing import List, Dict, Any, Optional
from datetime import datetime
from dataclasses import dataclass

@dataclass
class SIEMEvent:
    """Représente un événement SIEM."""
    timestamp: datetime
    event_type: str
    severity: str
    source: str
    details: Dict[str, Any]

class SIEMConnector:
    """Connecteur pour l'envoi d'événements vers un SIEM."""
    
    def __init__(self, host: str, port: int, token: str):
        """Initialise le connecteur SIEM.
        
        Args:
            host: Hôte du SIEM
            port: Port du SIEM
            token: Token d'authentification
        """
        self.host = host
        self.port = port
        self.token = token
        self.logger = logging.getLogger(__name__)
        self.base_url = f"http://{host}:{port}"
        
    def send_events(self, events: List[Any]) -> bool:
        """Envoie des événements au SIEM.
        
        Args:
            events: Liste des événements à envoyer
            
        Returns:
            True si l'envoi a réussi, False sinon
        """
        try:
            # Convertir les événements en format SIEM
            siem_events = [self._convert_to_siem_event(e) for e in events]
            
            # Envoyer les événements
            response = requests.post(
                f"{self.base_url}/api/events",
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Content-Type": "application/json"
                },
                json=siem_events
            )
            
            if response.status_code == 200:
                self.logger.info(f"{len(events)} événements envoyés au SIEM")
                return True
            else:
                self.logger.error(
                    f"Erreur lors de l'envoi au SIEM: {response.status_code} - {response.text}"
                )
                return False
                
        except Exception as e:
            self.logger.error(f"Erreur lors de l'envoi au SIEM: {str(e)}")
            return False
            
    def _convert_to_siem_event(self, event: Any) -> Dict[str, Any]:
        """Convertit un événement en format SIEM.
        
        Args:
            event: Événement à convertir
            
        Returns:
            Événement au format SIEM
        """
        return {
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type,
            "severity": event.severity,
            "source": "memory_analyzer",
            "details": event.details
        } 