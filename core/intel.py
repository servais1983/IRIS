import requests
import json
import time
import os
from core.utils import log_event

class ThreatIntelAPI:
    """Classe de base pour les intégrations d'API de threat intelligence"""
    def __init__(self, api_key=None, api_url=None):
        self.api_key = api_key
        self.api_url = api_url
        self.name = "GenericThreatIntel"
    
    def check_indicator(self, indicator):
        """Méthode à implémenter par les classes enfants"""
        raise NotImplementedError("Cette méthode doit être implémentée par les sous-classes")

class AlienVaultOTX(ThreatIntelAPI):
    """Intégration avec l'API Open Threat Exchange d'AlienVault"""
    def __init__(self, api_key=None):
        super().__init__(
            api_key=api_key or os.getenv("ALIENVAULT_API_KEY"),
            api_url="https://otx.alienvault.com/api/v1/indicators"
        )
        self.name = "AlienVault OTX"
    
    def check_indicator(self, indicator):
        """Vérifie un indicateur dans AlienVault OTX"""
        # Déterminer le type d'indicateur (IP, domaine, fichier, etc.)
        indicator_type = self._determine_indicator_type(indicator)
        
        if not indicator_type:
            return {"error": f"Type d'indicateur non supporté pour: {indicator}"}
        
        # Construire l'URL de l'API
        url = f"{self.api_url}/{indicator_type}/{indicator}"
        
        # En-têtes avec la clé API si disponible
        headers = {}
        if self.api_key:
            headers["X-OTX-API-KEY"] = self.api_key
        
        try:
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                
                # Extraire les informations pertinentes
                result = {
                    "found": True,
                    "source": self.name,
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "first_seen": data.get("first_seen"),
                    "last_seen": data.get("last_seen"),
                    "threat_score": data.get("reputation", 0)
                }
                
                # Ajouter des détails spécifiques selon le type d'indicateur
                if indicator_type == "domain" or indicator_type == "hostname":
                    result["malware"] = data.get("malware", {}).get("count", 0)
                    result["categories"] = [p.get("name") for p in data.get("pulse_info", {}).get("pulses", [])]
                
                elif indicator_type == "ip":
                    result["country"] = data.get("country_name")
                    result["asn"] = data.get("asn")
                
                elif indicator_type == "file":
                    result["malware_names"] = data.get("malware", {}).get("family", [])
                
                return result
            
            elif response.status_code == 404:
                return {"found": False, "source": self.name}
            
            else:
                return {"error": f"Erreur API {response.status_code}: {response.text}", "source": self.name}
        
        except Exception as e:
            return {"error": str(e), "source": self.name}
    
    def _determine_indicator_type(self, indicator):
        """Détermine le type d'indicateur pour l'API OTX"""
        # Vérifier si c'est une adresse IP (IPv4)
        if all(c.isdigit() or c == '.' for c in indicator) and indicator.count('.') == 3:
            return "IPv4"
        
        # Vérifier si c'est un hash MD5/SHA1/SHA256
        if all(c.isalnum() for c in indicator):
            if len(indicator) == 32:
                return "file"  # MD5
            if len(indicator) == 40:
                return "file"  # SHA1
            if len(indicator) == 64:
                return "file"  # SHA256
        
        # Vérifier si c'est un domaine
        if '.' in indicator and all(part.isalnum() or '-' in part for part in indicator.split('.')):
            return "domain"
        
        # Type non déterminé
        return None

class MISP(ThreatIntelAPI):
    """Intégration avec l'API MISP (Malware Information Sharing Platform)"""
    def __init__(self, api_key=None, api_url=None):
        super().__init__(
            api_key=api_key or os.getenv("MISP_API_KEY"),
            api_url=api_url or os.getenv("MISP_URL", "http://localhost/misp/events/restSearch")
        )
        self.name = "MISP"
    
    def check_indicator(self, indicator):
        """Vérifie un indicateur dans MISP"""
        # Sans clé API, impossible d'interroger MISP
        if not self.api_key:
            return {"error": "Clé API MISP manquante", "source": self.name}
        
        # En-têtes avec la clé API
        headers = {
            "Authorization": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
        # Payload de la requête
        payload = {
            "returnFormat": "json",
            "value": indicator
        }
        
        try:
            response = requests.post(self.api_url, headers=headers, json=payload)
            
            if response.status_code == 200:
                data = response.json()
                
                # Aucun événement trouvé
                if not data:
                    return {"found": False, "source": self.name}
                
                # Traiter les événements
                events_count = len(data.get("response", []))
                
                result = {
                    "found": events_count > 0,
                    "source": self.name,
                    "events_count": events_count
                }
                
                # Ajouter des informations détaillées si des événements sont trouvés
                if events_count > 0:
                    events = data.get("response", [])
                    result["first_seen"] = min(e.get("date", "") for e in events if "date" in e)
                    result["last_seen"] = max(e.get("date", "") for e in events if "date" in e)
                    result["threat_level"] = max(int(e.get("threat_level_id", 0)) for e in events)
                    result["event_ids"] = [e.get("id") for e in events]
                
                return result
            
            else:
                return {"error": f"Erreur API {response.status_code}: {response.text}", "source": self.name}
        
        except Exception as e:
            return {"error": str(e), "source": self.name}

def threat_intel_check(session, indicators):
    """
    Vérifie les indicateurs de compromission (IOCs) dans différentes sources de threat intelligence.
    
    Args:
        session (str): Identifiant de la session d'investigation
        indicators (list): Liste des indicateurs à vérifier (IPs, domaines, hashes, etc.)
    """
    print("[*] Vérification Threat Intelligence...")
    
    # Initialiser les API de threat intelligence
    intel_sources = [
        AlienVaultOTX(),
        MISP()
    ]
    
    results = {}
    
    # Pour chaque indicateur, vérifier toutes les sources
    for indicator in indicators:
        print(f"[*] Vérification de {indicator}...")
        indicator_results = {}
        
        for source in intel_sources:
            try:
                # Vérifier l'indicateur dans cette source
                source_result = source.check_indicator(indicator)
                
                # Ajouter le résultat
                indicator_results[source.name] = source_result
                
                # Afficher le résultat
                if source_result.get("found", False):
                    threat_level = source_result.get("threat_score", 0) or source_result.get("threat_level", 0)
                    print(f"[!] {indicator} trouvé dans {source.name} avec niveau de menace {threat_level}")
                elif "error" in source_result:
                    print(f"[!] Erreur lors de la vérification de {indicator} dans {source.name}: {source_result['error']}")
                else:
                    print(f"[+] {indicator} non trouvé dans {source.name}")
                
                # Petit délai pour ne pas surcharger les API
                time.sleep(0.5)
                
            except Exception as e:
                error_message = str(e)
                indicator_results[source.name] = {"error": error_message}
                print(f"[!] Exception lors de la vérification de {indicator} dans {source.name}: {error_message}")
        
        # Ajouter les résultats pour cet indicateur
        results[indicator] = indicator_results
    
    # Enregistrer tous les résultats
    log_event(session, "THREAT_INTEL", results)
    
    return results
