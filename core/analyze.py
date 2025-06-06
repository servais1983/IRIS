import psutil
import platform
import logging
from typing import List, Dict, Any, Set, Optional, Tuple, Union
from datetime import datetime, timedelta
from core.utils import log_event
import os
import re
import socket
import json
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
from core.report import ReportGenerator

class ProcessCategory(Enum):
    """Catégories de processus."""
    SYSTEM = "system"
    USER = "user"
    SERVICE = "service"
    SECURITY = "security"
    BROWSERS = "browsers"
    DEVELOPMENT = "development"
    UTILITIES = "utilities"

@dataclass
class ProcessInfo:
    """Informations sur un processus."""
    pid: int
    name: str
    username: str
    memory_percent: float
    cpu_percent: float
    create_time: Optional[datetime]
    cmdline: List[str]
    is_suspicious: bool = False
    suspicious_reasons: List[str] = field(default_factory=list)
    parent_pid: Optional[int] = None
    parent_name: Optional[str] = None
    network_connections: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        if self.suspicious_reasons is None:
            self.suspicious_reasons = []

class MemoryAnalyzerError(Exception):
    """Exception de base pour les erreurs de l'analyseur de mémoire."""
    pass

class ProcessAccessError(MemoryAnalyzerError):
    """Erreur lors de l'accès à un processus."""
    pass

class NetworkAnalysisError(MemoryAnalyzerError):
    """Erreur lors de l'analyse réseau."""
    pass

class ConfigurationError(MemoryAnalyzerError):
    """Erreur lors de la configuration."""
    pass

class MemoryAnalyzer:
    """Analyseur de mémoire pour la détection d'anomalies"""
    
    # Constantes pour les seuils
    CPU_THRESHOLD = 80.0
    MEMORY_THRESHOLD = 50.0
    RECENT_PROCESS_HOURS = 1
    
    # Ports suspects avec contexte
    SUSPICIOUS_PORTS = {
        'common': {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            445: 'SMB',
            1433: 'MSSQL',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            27017: 'MongoDB'
        },
        'malware': {
            4444: 'Metasploit',
            8080: 'Web Shell',
            1337: 'Backdoor',
            31337: 'Backdoor'
        }
    }
    
    # IPs suspectes avec contexte
    SUSPICIOUS_IPS = {
        '0.0.0.0': 'Toutes les interfaces',
        '127.0.0.1': 'Localhost',
        '192.168.1.1': 'Routeur local'
    }
    
    # Patterns de noms suspects avec contexte
    SUSPICIOUS_NAME_PATTERNS = {
        'crypt': 'Possible cryptominer',
        'miner': 'Possible cryptominer',
        'bot': 'Possible botnet',
        'backdoor': 'Possible backdoor',
        'trojan': 'Possible trojan',
        'malware': 'Possible malware',
        'virus': 'Possible virus',
        'worm': 'Possible worm',
        'rootkit': 'Possible rootkit',
        'keylogger': 'Possible keylogger',
        'spyware': 'Possible spyware',
        'hack': 'Possible outil de hacking',
        'exploit': 'Possible exploit',
        'inject': 'Possible injection',
        'payload': 'Possible payload malveillant',
        'shell': 'Possible shell malveillant'
    }
    
    def __init__(self, output_dir: Union[str, Path], log_file: Optional[Union[str, Path]] = None):
        """Initialise l'analyseur de mémoire.
        
        Args:
            output_dir: Dossier de sortie pour les résultats
            log_file: Fichier de log (optionnel)
            
        Raises:
            ValueError: Si le dossier de sortie est vide
            NotImplementedError: Si le système d'exploitation n'est pas supporté
            ConfigurationError: Si la configuration échoue
        """
        if not output_dir:
            raise ValueError("Le dossier de sortie ne peut pas être vide")
            
        self.output_dir = Path(output_dir)
        if not self.output_dir.exists():
            raise ConfigurationError(f"Le répertoire de sortie {output_dir} n'existe pas")
            
        self.whitelist = {}
        self.logger = logging.getLogger(__name__)
        
        try:
            self._setup_logging(log_file)
            self._load_whitelist()
            self._load_known_good_processes()
            
            # Vérifier que le système est supporté
            self.system = platform.system().lower()
            if self.system not in ['windows', 'linux']:
                raise ConfigurationError(f"Système d'exploitation non supporté: {self.system}")
                
        except Exception as e:
            raise ConfigurationError(f"Erreur lors de l'initialisation: {str(e)}")
    
    def _load_known_good_processes(self) -> None:
        """Charge la liste des processus connus comme légitimes.
        
        Cette liste est utilisée pour réduire les faux positifs.
        """
        self.known_good_processes = {
            'windows': {
                'system': ['System', 'System Idle Process', 'Registry', 'Memory Compression'],
                'services': ['svchost.exe', 'spoolsv.exe', 'lsass.exe', 'winlogon.exe', 'csrss.exe', 'smss.exe'],
                'security': ['MsMpEng.exe', 'NisSrv.exe', 'MpCmdRun.exe', 'WindowsDefender.exe'],
                'browsers': ['chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe'],
                'development': ['python.exe', 'node.exe', 'java.exe', 'javaw.exe', 'code.exe', 'devenv.exe'],
                'utilities': ['powershell.exe', 'cmd.exe', 'notepad.exe', 'calc.exe']
            },
            'linux': {
                'system': ['systemd', 'init', 'kthreadd', 'ksoftirqd', 'migration', 'watchdog'],
                'services': ['sshd', 'cron', 'rsyslogd', 'dbus-daemon', 'NetworkManager'],
                'security': ['auditd', 'firewalld', 'ufw', 'clamd', 'clamav'],
                'browsers': ['chrome', 'firefox', 'chromium', 'opera'],
                'development': ['python', 'node', 'java', 'gcc', 'make'],
                'utilities': ['bash', 'sh', 'zsh', 'vim', 'nano']
            }
        }
    
    def _load_whitelist(self) -> None:
        """Charge la liste blanche depuis le fichier de configuration."""
        try:
            with open("config/whitelist.json", "r") as f:
                whitelist = json.load(f)
                # Convertir les clés en str
                self.whitelist = {
                    os: {
                        str(category): processes
                        for category, processes in categories.items()
                    }
                    for os, categories in whitelist.items()
                }
        except Exception as e:
            self.logger.error(f"Erreur lors du chargement de la liste blanche: {str(e)}")
            self.whitelist = {}
    
    def _setup_logging(self, log_file: Optional[Union[str, Path]] = None) -> None:
        """Configure le logging pour le module.
        
        Args:
            log_file: Chemin du fichier de log (optionnel)
            
        Raises:
            RuntimeError: Si la configuration du logging échoue
        """
        if log_file is None:
            log_file = self.output_dir / "memory_analysis.log"
        else:
            log_file = Path(log_file)
            
        try:
            # Supprimer les handlers existants
            for handler in self.logger.handlers[:]:
                self.logger.removeHandler(handler)
                handler.close()
            
            # Créer le dossier de sortie s'il n'existe pas
            log_file.parent.mkdir(parents=True, exist_ok=True)
            
            handler = logging.FileHandler(log_file)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
        except Exception as e:
            raise RuntimeError(f"Erreur lors de la configuration du logging: {str(e)}")
    
    def cleanup(self) -> None:
        """Nettoie les ressources utilisées par l'analyseur."""
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)
            handler.close()
    
    def analyze_processes(self) -> List[ProcessInfo]:
        """Analyse tous les processus en cours d'exécution.
        
        Returns:
            Liste des informations sur les processus suspects
        """
        suspicious_processes = []
        try:
            for process in psutil.process_iter(['pid', 'name', 'username', 'create_time']):
                try:
                    if self._is_suspicious_process(process):
                        process_info = self._get_process_info(process)
                        suspicious_processes.append(process_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse des processus: {str(e)}")
        return suspicious_processes
    
    def _is_suspicious_process(self, proc: psutil.Process) -> bool:
        """Vérifie si un processus est suspect.
        
        Args:
            proc: Processus à vérifier
            
        Returns:
            True si le processus est suspect
            
        Raises:
            ProcessAccessError: Si l'accès au processus échoue
        """
        try:
            # Vérifier si le processus est dans la liste blanche
            if self._is_whitelisted(proc.name()):
                return False
            
            # Vérifier si c'est un processus connu comme légitime
            if self._is_known_good_process(proc):
                return False
            
            # Critères de suspicion avec scores
            suspicion_score = 0
            reasons = []
            
            # 1. Vérifier l'utilisation des ressources (score: 2)
            cpu_percent = proc.cpu_percent(interval=0.1)
            memory_percent = proc.memory_percent()
            if cpu_percent > self.CPU_THRESHOLD or memory_percent > self.MEMORY_THRESHOLD:
                suspicion_score += 2
                reasons.append(f"Utilisation élevée des ressources (CPU: {cpu_percent}%, Mémoire: {memory_percent}%)")
            
            # 2. Vérifier le nom du processus (score: 3)
            if self._is_suspicious_name(proc.name()):
                suspicion_score += 3
                reasons.append(f"Nom suspect: {proc.name()}")
            
            # 3. Vérifier l'âge du processus (score: 1)
            if self._is_recently_created(proc):
                suspicion_score += 1
                reasons.append("Processus récemment créé")
            
            # 4. Vérifier les privilèges (score: 2)
            if self._has_elevated_privileges(proc):
                suspicion_score += 2
                reasons.append("Privilèges élevés")
            
            # 5. Vérifier la ligne de commande (score: 3)
            cmdline = proc.cmdline()
            if self._is_suspicious_cmdline(cmdline):
                suspicion_score += 3
                reasons.append(f"Ligne de commande suspecte: {' '.join(cmdline)}")
            
            # 6. Vérifier le processus parent (score: 2)
            parent = proc.parent()
            if parent and self._is_unusual_parent(parent):
                suspicion_score += 2
                reasons.append(f"Parent suspect: {parent.name()}")
            
            # 7. Vérifier les connexions réseau (score: 3)
            if self._has_suspicious_network_activity(proc):
                suspicion_score += 3
                reasons.append("Activité réseau suspecte")
            
            # Seuil de suspicion (score minimum: 5)
            is_suspicious = suspicion_score >= 5
            
            # Si le processus est suspect, logger les raisons avec le score
            if is_suspicious:
                self.logger.warning(f"Processus suspect détecté: {proc.name()} (PID: {proc.pid}, Score: {suspicion_score})")
                for reason in reasons:
                    self.logger.warning(f"  - {reason}")
            
            return is_suspicious
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired) as e:
            self.logger.warning(f"Erreur lors de l'analyse du processus: {str(e)}")
            raise ProcessAccessError(f"Erreur lors de l'analyse du processus: {str(e)}")
    
    def _is_suspicious_name(self, name: str) -> bool:
        """Vérifie si le nom du processus est suspect.
        
        Args:
            name: Nom du processus
            
        Returns:
            True si le nom est suspect
        """
        if not name:
            return False
            
        suspicious_patterns = [
            'crypt', 'miner', 'bot', 'backdoor', 'trojan', 'malware',
            'virus', 'worm', 'rootkit', 'keylogger', 'spyware',
            'hack', 'exploit', 'inject', 'payload', 'shell'
        ]
        return any(pattern in name.lower() for pattern in suspicious_patterns)
    
    def _is_recently_created(self, process: psutil.Process) -> bool:
        """Vérifie si le processus a été créé récemment.
        
        Args:
            process: Processus à vérifier
            
        Returns:
            True si le processus est récent
        """
        if not process.create_time():
            return False
            
        try:
            create_time = datetime.fromtimestamp(process.create_time())
            time_diff = datetime.now() - create_time
            return time_diff.total_seconds() < 3600  # Moins d'une heure
        except Exception as e:
            self.logger.error(f"Erreur lors de la vérification de l'âge du processus: {str(e)}")
            return False
    
    def _has_elevated_privileges(self, process: psutil.Process) -> bool:
        """Vérifie si un processus a des privilèges élevés."""
        try:
            username = process.username()
            return username.upper() == "SYSTEM"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
    
    def _is_suspicious_cmdline(self, cmdline: List[str]) -> bool:
        """Vérifie si une ligne de commande est suspecte."""
        suspicious_patterns = [
            "rm -rf", "format", "del /f /s",
            "net user", "net group", "net localgroup",
            "powershell -enc", "python -c",
            "wget", "curl", "nc", "netcat"
        ]
        cmdline_str = " ".join(cmdline).lower()
        return any(pattern in cmdline_str for pattern in suspicious_patterns)
    
    def _is_unusual_parent(self, parent: psutil.Process) -> bool:
        """Vérifie si le processus a un parent inhabituel.
        
        Args:
            parent: Processus parent à vérifier
            
        Returns:
            True si le parent est inhabituel
            
        Raises:
            ProcessAccessError: Si l'accès au processus échoue
        """
        try:
            # Liste des parents légitimes
            legitimate_parents = {
                'windows': ['explorer.exe', 'svchost.exe', 'services.exe', 'wininit.exe'],
                'linux': ['systemd', 'init', 'bash', 'sh', 'zsh']
            }
            
            return parent.name() not in legitimate_parents[self.system]
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.logger.warning(f"Impossible de vérifier le processus parent: {str(e)}")
            raise ProcessAccessError(f"Impossible de vérifier le processus parent: {str(e)}")
    
    def _has_suspicious_network_activity(self, process: psutil.Process) -> bool:
        """Vérifie si un processus a une activité réseau suspecte."""
        try:
            connections = process.connections()
            suspicious_ports = [4444, 1337, 31337]
            suspicious_ips = ["1.2.3.4", "5.6.7.8"]
            
            for conn in connections:
                if conn.laddr and conn.laddr.port in suspicious_ports:
                    return True
                if conn.raddr and (conn.raddr.port in suspicious_ports or conn.raddr.ip in suspicious_ips):
                    return True
            return False
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
    
    def _is_whitelisted(self, process_name: str) -> bool:
        """Vérifie si un processus est dans la liste blanche."""
        if not self.whitelist:
            return False
        for category in self.whitelist.get(self.system, {}).values():
            if process_name in category:
                return True
        return False
    
    def _is_known_good_process(self, proc: Union[psutil.Process, str]) -> bool:
        """Vérifie si un processus est connu comme légitime.
        
        Args:
            proc: Processus à vérifier
            
        Returns:
            True si le processus est connu comme légitime
        """
        try:
            # Si c'est un objet Process, obtenir le nom
            if hasattr(proc, 'name'):
                name = proc.name()
            else:
                name = proc
                
            if not name:
                return False
                
            # Vérifier dans la liste des processus connus
            for category in self.known_good_processes[self.system].values():
                if name.lower() in [p.lower() for p in category]:
                    return True
                    
            return False
            
        except Exception as e:
            self.logger.warning(f"Erreur lors de la vérification du processus connu: {str(e)}")
            return False
    
    def analyze_memory_usage(self) -> Dict[str, Any]:
        """Analyse l'utilisation de la mémoire.
        
        Returns:
            Dict contenant les informations sur la mémoire
            
        Raises:
            RuntimeError: Si l'analyse de la mémoire échoue
        """
        try:
            vm = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            return {
                "total_memory": vm.total,
                "available_memory": vm.available,
                "memory_percent": vm.percent,
                "swap_total": swap.total,
                "swap_used": swap.used,
                "swap_percent": swap.percent,
                "analysis_time": datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse de la mémoire: {str(e)}")
            raise RuntimeError(f"Erreur lors de l'analyse de la mémoire: {str(e)}")
    
    def analyze_network_connections(self) -> Dict[str, Any]:
        """Analyse les connexions réseau.
        
        Returns:
            Dict contenant les informations sur les connexions réseau
            
        Raises:
            NetworkAnalysisError: Si l'analyse réseau échoue
        """
        try:
            connections = psutil.net_connections()
            suspicious = []
            
            for conn in connections:
                if self._is_suspicious_connection(conn):
                    suspicious.append({
                        "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                        "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        "status": conn.status,
                        "pid": conn.pid
                    })
            
            return {
                "total_connections": len(connections),
                "suspicious_connections": suspicious,
                "analysis_time": datetime.now().isoformat()
            }
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse des connexions réseau: {str(e)}")
            raise NetworkAnalysisError(f"Erreur lors de l'analyse des connexions réseau: {str(e)}")
    
    def _is_suspicious_connection(self, conn: psutil._common.sconn) -> bool:
        """Vérifie si une connexion est suspecte.
        
        Args:
            conn: Connexion à vérifier
            
        Returns:
            True si la connexion est suspecte
        """
        try:
            # Vérifier les ports suspects
            if conn.laddr and conn.laddr.port in self.SUSPICIOUS_PORTS['malware']:
                return True
            if conn.raddr and conn.raddr.port in self.SUSPICIOUS_PORTS['malware']:
                return True
                
            # Vérifier les IPs suspectes
            if conn.raddr and conn.raddr.ip in self.SUSPICIOUS_IPS:
                return True
                
            return False
        except Exception as e:
            self.logger.warning(f"Erreur lors de la vérification de la connexion: {str(e)}")
            return False

    def _is_whitelisted_port(self, port: int) -> bool:
        """Vérifie si un port est dans la liste blanche."""
        return port in self.whitelist.get("ports", [])

    def _is_whitelisted_ip(self, ip: str) -> bool:
        """Vérifie si une IP est dans la liste blanche."""
        return ip in self.whitelist.get("ips", [])

    def _get_process_info(self, process: psutil.Process) -> ProcessInfo:
        """Récupère les informations d'un processus."""
        try:
            return ProcessInfo(
                pid=process.pid,
                name=process.name(),
                username=process.username(),
                memory_percent=process.memory_percent(),
                cpu_percent=process.cpu_percent(),
                create_time=datetime.fromtimestamp(process.create_time()),
                cmdline=process.cmdline(),
                is_suspicious=self._is_suspicious_process(process),
                suspicious_reasons=self._get_suspicious_reasons(process)
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            raise ProcessAccessError(f"Impossible d'accéder au processus {process.pid}: {e}")

    def save_results(self, results: dict, output_file: str = None) -> None:
        """Sauvegarde les résultats de l'analyse dans un fichier JSON."""
        if output_file is None:
            output_file = os.path.join(self.output_dir, "analysis_results.json")
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, default=str, indent=4)
            self.logger.info(f"Résultats sauvegardés dans {output_file}")
        except Exception as e:
            self.logger.error(f"Erreur lors de la sauvegarde des résultats: {e}")
            raise

    def analyze_network(self) -> dict:
        """Analyse les connexions réseau et retourne un dictionnaire de résultats."""
        results = {
            "connections": [],
            "suspicious_connections": []
        }
        try:
            for conn in psutil.net_connections():
                if conn.pid is None:
                    continue
                try:
                    process = psutil.Process(conn.pid)
                    conn_info = {
                        "pid": conn.pid,
                        "process_name": process.name(),
                        "local_address": f"{conn.laddr.ip}:{conn.laddr.port}" if hasattr(conn.laddr, 'ip') else str(conn.laddr),
                        "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if hasattr(conn.raddr, 'ip') else str(conn.raddr),
                        "status": conn.status
                    }
                    if self._has_suspicious_network_activity(process):
                        results["suspicious_connections"].append(conn_info)
                    else:
                        results["connections"].append(conn_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse réseau: {e}")
        return results

    def _get_suspicious_reasons(self, process: psutil.Process) -> List[str]:
        """Récupère les raisons pour lesquelles un processus est suspect."""
        reasons = []
        try:
            if self._has_elevated_privileges(process):
                reasons.append("Privilèges élevés")
            if self._has_suspicious_network_activity(process):
                reasons.append("Activité réseau suspecte")
            if self._is_suspicious_name(process.name()):
                reasons.append("Nom suspect")
            if self._is_suspicious_cmdline(process.cmdline()):
                reasons.append("Ligne de commande suspecte")
            if self._is_recently_created(process):
                reasons.append("Créé récemment")
            if self._is_unusual_parent(process):
                reasons.append("Parent inhabituel")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            reasons.append("Erreur d'accès")
        return reasons

    def generate_report(self, format="html", include_network=True, include_processes=True, include_timeline=True):
        """Génère un rapport de sécurité via ReportGenerator."""
        generator = ReportGenerator(self.output_dir)
        return generator.generate_report(format=format, include_network=include_network, include_processes=include_processes, include_timeline=include_timeline)

    def get_recent_events(self, minutes: int = 5) -> List[Dict[str, Any]]:
        """Récupère les événements récents du moniteur de sécurité.
        
        Args:
            minutes: Nombre de minutes à remonter
            
        Returns:
            Liste des événements récents
        """
        if hasattr(self, 'monitor') and self.monitor:
            return self.monitor.get_recent_events(minutes)
        return []

def memory_forensics(investigation_id: str) -> Dict[str, Any]:
    """
    Effectue une analyse forensique de la mémoire du système.
    
    Args:
        investigation_id: ID de l'investigation
        
    Returns:
        Dict contenant les résultats de l'analyse
        
    Raises:
        ValueError: Si l'ID d'investigation est vide
        RuntimeError: Si l'analyse échoue
    """
    if not investigation_id:
        raise ValueError("ID d'investigation vide")
        
    logger = logging.getLogger(__name__)
    logger.info("[*] Analyse mémoire en cours...")
    
    try:
        # Créer le dossier de sortie pour cette investigation
        output_dir = Path("evidence") / investigation_id
        output_dir.mkdir(parents=True, exist_ok=True)
        
        analyzer = MemoryAnalyzer(output_dir)
        results = {
            "processes": analyzer.analyze_processes(),
            "memory_usage": analyzer.analyze_memory_usage(),
            "network_connections": analyzer.analyze_network_connections(),
            "analysis_time": datetime.now().isoformat()
        }
        
        # Enregistrer les résultats
        log_event(investigation_id, "MEMORY_FORENSICS", results)
        
        # Sauvegarder les résultats dans un fichier JSON
        results_file = output_dir / "memory_analysis.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=4)
        
        # Afficher le résumé
        if results["processes"]:
            logger.warning(f"[!] {len(results['processes'])} processus suspects détectés:")
            for proc in results["processes"]:
                logger.warning(f"    - PID {proc['pid']}: {proc['name']} ({proc['username']})")
        
        if results["network_connections"].get("suspicious_connections"):
            logger.warning(f"[!] {len(results['network_connections']['suspicious_connections'])} connexions suspectes détectées")
        
        return results
        
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse mémoire: {str(e)}")
        raise RuntimeError(f"Erreur lors de l'analyse mémoire: {str(e)}")
    finally:
        if 'analyzer' in locals():
            analyzer.cleanup()
