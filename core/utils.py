import os
import hashlib
import json
from datetime import datetime
import logging
from typing import Dict, Any, Optional
from rich.logging import RichHandler

def init_session(prefix):
    """
    Initialise une nouvelle session d'investigation avec un identifiant unique basé sur la date et l'heure.
    Crée le dossier de destination pour les preuves.
    
    Args:
        prefix (str): Préfixe pour le nom du dossier
        
    Returns:
        str: Identifiant unique de la session
    """
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    folder = f"{prefix}_{ts}"
    os.makedirs(f"evidence/{folder}", exist_ok=True)
    return folder

def setup_logging():
    """Configure le système de logging avec Rich"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True)]
    )

def log_event(investigation_id: str, event_type: str, data: Dict[str, Any]):
    """
    Enregistre un événement dans le journal de l'investigation.
    
    Args:
        investigation_id: ID de l'investigation
        event_type: Type d'événement
        data: Données de l'événement
    """
    log_dir = os.path.join("evidence", investigation_id, "logs")
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, "investigation.log")
    
    event = {
        "timestamp": datetime.now().isoformat(),
        "type": event_type,
        "data": data
    }
    
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")

def calculate_file_hash(file_path: str) -> Dict[str, Optional[str]]:
    """
    Calcule les hashes MD5, SHA1 et SHA256 d'un fichier.
    
    Args:
        file_path: Chemin du fichier
        
    Returns:
        Dict contenant les hashes (peuvent être None en cas d'erreur)
    """
    hashes = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256()
    }
    
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                for hash_obj in hashes.values():
                    hash_obj.update(chunk)
        
        return {
            "md5": hashes["md5"].hexdigest(),
            "sha1": hashes["sha1"].hexdigest(),
            "sha256": hashes["sha256"].hexdigest()
        }
    except Exception as e:
        logging.error(f"Erreur lors du calcul des hashes pour {file_path}: {str(e)}")
        return {
            "md5": None,
            "sha1": None,
            "sha256": None,
            "error": str(e)
        }

def create_chain_of_custody(investigation_id: str, file_path: str, original_path: str, collector: str):
    """
    Crée une entrée dans la chaîne de possession pour un fichier.
    
    Args:
        investigation_id: ID de l'investigation
        file_path: Chemin du fichier collecté
        original_path: Chemin original du fichier
        collector: Identifiant du collecteur
    """
    chain_dir = os.path.join("evidence", investigation_id, "chain_of_custody")
    os.makedirs(chain_dir, exist_ok=True)
    
    chain_file = os.path.join(chain_dir, "chain.json")
    
    entry = {
        "timestamp": datetime.now().isoformat(),
        "file_path": file_path,
        "original_path": original_path,
        "collector": collector,
        "hashes": calculate_file_hash(file_path)
    }
    
    try:
        if os.path.exists(chain_file):
            with open(chain_file, "r", encoding="utf-8") as f:
                chain = json.load(f)
        else:
            chain = []
        
        chain.append(entry)
        
        with open(chain_file, "w", encoding="utf-8") as f:
            json.dump(chain, f, indent=2, ensure_ascii=False)
            
    except Exception as e:
        logging.error(f"Erreur lors de la création de la chaîne de possession: {str(e)}")
