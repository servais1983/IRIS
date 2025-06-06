import os
import platform
import subprocess
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from core.utils import log_event

class NetworkContainment:
    """Gestion du containment réseau"""
    
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.logger = logging.getLogger(__name__)
        self.system = platform.system().lower()
        self.is_admin = self._is_admin()
        self.blocked_ips: List[str] = []
        self.hosts_file = r"C:\Windows\System32\drivers\etc\hosts" if platform.system() == "Windows" else "/etc/hosts"
        self.log_handler = None
        self._setup_logging()
        
    def _setup_logging(self) -> None:
        """Configure la journalisation"""
        log_file = os.path.join(self.output_dir, "containment.log")
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        self.log_handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.log_handler.setFormatter(formatter)
        
        self.logger.addHandler(self.log_handler)
        self.logger.setLevel(logging.INFO)
    
    def cleanup(self):
        """Nettoie les ressources utilisées."""
        if self.log_handler:
            self.logger.removeHandler(self.log_handler)
            self.log_handler.close()
            self.log_handler = None
    
    def _is_admin(self) -> bool:
        """Vérifie si l'utilisateur a les droits administrateur"""
        try:
            if self.system == 'windows':
                return subprocess.run(["net", "session"], capture_output=True).returncode == 0
            else:
                # Vérifier les droits root en essayant d'exécuter une commande qui nécessite des privilèges
                result = subprocess.run(['id', '-u'], capture_output=True, text=True)
                return result.stdout.strip() == '0'
        except Exception as e:
            self.logger.error(f"Erreur lors de la vérification des droits admin: {str(e)}")
            return False
    
    def _block_ip_windows(self, ip: str) -> bool:
        """Bloque une IP sous Windows"""
        try:
            if not self.is_admin:
                self.logger.warning("Droits administrateur requis pour bloquer les IPs")
                return False
                
            # Utiliser netsh pour bloquer l'IP
            cmd = f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}'
            subprocess.run(cmd, shell=True, check=True)
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Erreur lors du blocage de l'IP {ip}: {str(e)}")
            return False
        except Exception as e:
            self.logger.error(f"Erreur inattendue lors du blocage de l'IP {ip}: {str(e)}")
            return False
    
    def _block_ip_linux(self, ip: str) -> bool:
        """Bloque une IP sous Linux"""
        try:
            if not self.is_admin:
                self.logger.warning("Droits administrateur requis pour bloquer les IPs")
                return False
                
            # Utiliser iptables pour bloquer l'IP
            cmd = f'iptables -A INPUT -s {ip} -j DROP'
            subprocess.run(cmd, shell=True, check=True)
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Erreur lors du blocage de l'IP {ip}: {str(e)}")
            return False
        except Exception as e:
            self.logger.error(f"Erreur inattendue lors du blocage de l'IP {ip}: {str(e)}")
            return False
    
    def _block_ip_hosts_file(self, ip: str) -> bool:
        """Bloque une IP en modifiant le fichier hosts."""
        try:
            with open(self.hosts_file, 'a') as f:
                f.write(f"\n{ip} localhost")
            return True
        except Exception as e:
            self.logger.error(f"Erreur lors de la modification du fichier hosts: {str(e)}")
            return False
    
    def block_ips(self, ips: List[str], investigation_id: str) -> Dict[str, Any]:
        """Bloque une liste d'IPs suspectes"""
        results = {
            "blocked": [],
            "failed": [],
            "block_time": datetime.now().isoformat()
        }
        
        for ip in ips:
            if ip in self.blocked_ips:
                continue
                
            try:
                # Essayer d'abord la méthode principale
                if self.system == 'windows':
                    success = self._block_ip_windows(ip)
                else:
                    success = self._block_ip_linux(ip)
                
                # Si échec et pas de droits admin, essayer la méthode alternative
                if not success and not self.is_admin:
                    success = self._block_ip_hosts_file(ip)
                
                if success:
                    self.blocked_ips.append(ip)
                    results["blocked"].append(ip)
                    log_event(investigation_id, "containment", {"status": "success", "ip": ip})
                else:
                    results["failed"].append(ip)
                    log_event(investigation_id, "containment", {"status": "failed", "ip": ip})
                    
            except Exception as e:
                self.logger.error(f"Erreur lors du blocage de l'IP {ip}: {str(e)}")
                results["failed"].append(ip)
        
        return results
    
    def unblock_ips(self, ips: List[str]) -> Dict[str, Any]:
        """Débloque une liste d'IPs"""
        results = {
            "unblocked": [],
            "failed": [],
            "unblock_time": datetime.now().isoformat()
        }
        
        for ip in ips:
            if ip not in self.blocked_ips:
                continue
                
            try:
                if self.system == 'windows':
                    cmd = f'netsh advfirewall firewall delete rule name="Block {ip}"'
                else:
                    cmd = f'iptables -D INPUT -s {ip} -j DROP'
                
                if self.is_admin:
                    subprocess.run(cmd, shell=True, check=True)
                    results["unblocked"].append(ip)
                else:
                    # Nettoyer le fichier hosts local
                    with open(self.hosts_file, 'r') as f:
                        lines = f.readlines()
                    with open(self.hosts_file, 'w') as f:
                        f.writelines([l for l in lines if ip not in l])
                    results["unblocked"].append(ip)
                        
            except Exception as e:
                self.logger.error(f"Erreur lors du déblocage de l'IP {ip}: {str(e)}")
                results["failed"].append(ip)
        
        return results
    
    def isolate_system(self, system_id: str) -> bool:
        """Isole un système du réseau"""
        try:
            if not self.is_admin:
                self.logger.warning("Droits administrateur requis pour isoler le système")
                return False
            
            if self.system == 'windows':
                # Désactiver toutes les interfaces réseau
                cmd = 'netsh interface set interface "Ethernet" admin=disable'
                subprocess.run(cmd, shell=True, check=True)
                cmd = 'netsh interface set interface "Wi-Fi" admin=disable'
                subprocess.run(cmd, shell=True, check=True)
            else:
                # Désactiver toutes les interfaces réseau
                cmd = 'ifconfig | grep -E "^[a-z0-9]+:" | cut -d: -f1 | xargs -I {} ifconfig {} down'
                subprocess.run(cmd, shell=True, check=True)
            
            self.logger.info(f"Système {system_id} isolé avec succès")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur lors de l'isolation du système {system_id}: {str(e)}")
            return False

    def restore_network(self) -> bool:
        """Restaure les connexions réseau."""
        try:
            if self.system == "windows":
                # Réactive toutes les interfaces réseau
                cmd = 'netsh interface set interface "Ethernet" admin=enable'
                subprocess.run(cmd, shell=True, check=True)
                cmd = 'netsh interface set interface "Wi-Fi" admin=enable'
                subprocess.run(cmd, shell=True, check=True)
            else:
                # Réactive toutes les interfaces réseau sur Linux
                cmd = 'ifconfig | grep -E "^[a-z0-9]+:" | cut -d: -f1 | xargs -I {} ifconfig {} up'
                subprocess.run(cmd, shell=True, check=True)
            
            self.logger.info("Réseau restauré avec succès")
            return True
        except Exception as e:
            self.logger.error(f"Erreur lors de la restauration du réseau: {str(e)}")
            return False

def network_containment(investigation_id: str, malicious_ips: List[str], system_id: Optional[str] = None) -> Dict:
    """
    Gère le containment réseau et l'isolation des systèmes compromis.
    
    Args:
        investigation_id: ID de l'investigation
        malicious_ips: Liste des IPs à bloquer
        system_id: ID du système à isoler (optionnel)
    
    Returns:
        Dict contenant les résultats des opérations
    """
    print("[*] Containment réseau...")
    
    containment = NetworkContainment(investigation_id)
    results = {
        "blocked_ips": [],
        "failed_ips": [],
        "system_isolated": False
    }
    
    # Bloquer les IPs malveillantes
    for ip in malicious_ips:
        if containment.block_ips([ip], investigation_id)["blocked"]:
            results["blocked_ips"].append(ip)
        else:
            results["failed_ips"].append(ip)
    
    # Isoler le système si spécifié
    if system_id:
        results["system_isolated"] = containment.isolate_system(system_id)
    
    # Enregistrer les résultats
    log_event(investigation_id, "NETWORK_CONTAINMENT", results)
    
    # Afficher le résumé
    if results["blocked_ips"]:
        print(f"[+] {len(results['blocked_ips'])} IPs bloquées avec succès")
    if results["failed_ips"]:
        print(f"[!] {len(results['failed_ips'])} IPs n'ont pas pu être bloquées")
    if system_id:
        if results["system_isolated"]:
            print(f"[+] Système {system_id} isolé avec succès")
        else:
            print(f"[!] Échec de l'isolation du système {system_id}")
    
    return results

def disable_network_interface(session: str, interface_name: str) -> str:
    """
    Désactive une interface réseau spécifique en cas d'incident grave.
    
    Args:
        session (str): Identifiant de la session d'investigation
        interface_name (str): Nom de l'interface à désactiver
    """
    print(f"[*] Désactivation de l'interface réseau {interface_name}...")
    
    try:
        os_type = platform.system().lower()
        
        if os_type == "linux":
            cmd = f"ip link set {interface_name} down"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        elif os_type == "windows":
            cmd = f'netsh interface set interface "{interface_name}" disable'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        else:
            raise NotImplementedError(f"Système non supporté: {os_type}")
        
        if result.returncode == 0:
            print(f"[+] Interface {interface_name} désactivée")
            status = "disabled"
        else:
            print(f"[!] Échec de la désactivation de l'interface {interface_name}: {result.stderr}")
            status = "failed"
        
    except Exception as e:
        print(f"[!] Erreur lors de la désactivation de l'interface {interface_name}: {e}")
        status = "error"
    
    # Enregistrer l'action
    log_event(session, "NETWORK_INTERFACE_CONTAINMENT", {
        "interface": interface_name,
        "status": status,
        "os_type": os_type
    })
    
    return status
