import os
import shutil
import hashlib
import platform
import glob
from datetime import datetime
from core.utils import log_event, calculate_file_hash, create_chain_of_custody

def artifact_collection(session, quick=False):
    """
    Collecte les artefacts système pertinents pour l'analyse forensique.
    
    Args:
        session (str): Identifiant de la session d'investigation
        quick (bool): Si True, effectue une collecte minimale pour une analyse rapide
    """
    print("[*] Collecte des preuves systèmes...")
    
    # Définir les chemins à collecter selon le système d'exploitation
    os_type = platform.system().lower()
    
    if os_type == "linux":
        paths = [
            "/var/log/", 
            "/etc/passwd", 
            "/etc/shadow",
            "/root/.bash_history", 
            "/home/*/.bash_history",
            "/proc/net/tcp", 
            "/proc/net/udp",
            "/tmp",
            "/var/spool/cron",
            "/etc/crontab",
            "/var/log/auth.log",
            "/var/log/syslog"
        ]
        
        # En mode rapide, limiter la collecte aux fichiers les plus importants
        if quick:
            paths = [
                "/var/log/auth.log",
                "/var/log/syslog",
                "/etc/passwd",
                "/proc/net/tcp"
            ]
    
    elif os_type == "windows":
        # Chemins Windows pour les artefacts forensiques
        paths = [
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
            "C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
            "C:\\Windows\\System32\\winevt\\Logs\\Application.evtx",
            "C:\\Windows\\Prefetch\\",
            "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\",
            "C:\\Users\\*\\NTUSER.DAT",
            "C:\\$MFT",  # Nécessite des privilèges élevés
            "C:\\pagefile.sys"  # Nécessite des privilèges élevés
        ]
        
        # En mode rapide, limiter la collecte
        if quick:
            paths = [
                "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
                "C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
                "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\"
            ]
    
    else:
        # Pour les autres systèmes, collecter un ensemble minimal
        print(f"[!] Système d'exploitation {os_type} partiellement supporté")
        paths = [
            "/var/log/"
        ]
    
    # Préparer le dossier de destination
    dest_base = f"evidence/{session}/artifacts"
    os.makedirs(dest_base, exist_ok=True)
    
    # Identifiant du collecteur
    collector = f"IRIS-{os.getenv('USER', 'system')}"
    
    # Compteurs pour le rapport
    collected = 0
    failed = 0
    
    # Parcourir les chemins et collecter les artefacts
    for path_pattern in paths:
        # Résoudre les chemins avec des caractères joker (*)
        for path in glob.glob(path_pattern):
            if os.path.exists(path):
                try:
                    # Préparer le chemin de destination
                    rel_path = path.replace(":", "").replace("\\", "/").lstrip("/")
                    dst = os.path.join(dest_base, rel_path)
                    
                    # Créer les répertoires intermédiaires si nécessaire
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    
                    # Copier le fichier ou le répertoire
                    if os.path.isdir(path):
                        # Copier récursivement uniquement en mode complet
                        if not quick:
                            shutil.copytree(path, dst, dirs_exist_ok=True)
                            collected += 1
                    else:
                        shutil.copy2(path, dst)
                        collected += 1
                        
                        # Créer une entrée dans la chaîne de possession
                        create_chain_of_custody(session, dst, path, collector)
                
                except Exception as e:
                    error_msg = str(e)
                    log_event(session, "COLLECTION_ERROR", {"path": path, "error": error_msg})
                    failed += 1
                    print(f"[!] Erreur lors de la collecte de {path}: {error_msg}")
    
    # Enregistrer un résumé de la collecte
    collection_summary = {
        "collected": collected,
        "failed": failed,
        "system": os_type,
        "mode": "quick" if quick else "full",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    log_event(session, "ARTIFACT_COLLECTION_SUMMARY", collection_summary)
    
    print(f"[+] Collecte terminée: {collected} artefacts récupérés, {failed} échecs")
    return collection_summary
