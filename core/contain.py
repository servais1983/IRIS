import os
import subprocess
import platform
from core.utils import log_event

def network_containment(session, ips):
    """
    Implémente une isolation réseau en bloquant les IPs spécifiées 
    via les fonctionnalités de pare-feu du système.
    
    Args:
        session (str): Identifiant de la session d'investigation
        ips (list): Liste des adresses IP à bloquer
    """
    print("[*] Containment des IPs malveillantes...")
    
    # Déterminer le système d'exploitation
    os_type = platform.system().lower()
    blocked_ips = []
    failed_ips = []
    
    for ip in ips:
        try:
            # Vérifier la validité de l'adresse IP (implémentation basique)
            ip_parts = ip.split('.')
            if len(ip_parts) != 4:
                raise ValueError(f"Format IP invalide: {ip}")
            
            # Implémenter le blocage selon le système d'exploitation
            if os_type == "linux":
                # Utiliser iptables sur Linux
                cmd = f"iptables -A INPUT -s {ip} -j DROP && iptables -A OUTPUT -d {ip} -j DROP"
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                
                if result.returncode == 0:
                    blocked_ips.append(ip)
                    print(f"[+] IP bloquée: {ip}")
                else:
                    failed_ips.append({"ip": ip, "error": result.stderr})
                    print(f"[!] Échec du blocage de {ip}: {result.stderr}")
                
            elif os_type == "windows":
                # Utiliser Windows Firewall
                inbound_cmd = f'netsh advfirewall firewall add rule name="IRIS-Block-{ip}-In" dir=in action=block remoteip={ip}'
                outbound_cmd = f'netsh advfirewall firewall add rule name="IRIS-Block-{ip}-Out" dir=out action=block remoteip={ip}'
                
                in_result = subprocess.run(inbound_cmd, shell=True, capture_output=True, text=True)
                out_result = subprocess.run(outbound_cmd, shell=True, capture_output=True, text=True)
                
                if in_result.returncode == 0 and out_result.returncode == 0:
                    blocked_ips.append(ip)
                    print(f"[+] IP bloquée: {ip}")
                else:
                    error = in_result.stderr if in_result.returncode != 0 else out_result.stderr
                    failed_ips.append({"ip": ip, "error": error})
                    print(f"[!] Échec du blocage de {ip}: {error}")
            
            else:
                # Système non supporté
                failed_ips.append({"ip": ip, "error": f"Système non supporté: {os_type}"})
                print(f"[!] Système {os_type} non supporté pour le blocage IP")
        
        except Exception as e:
            failed_ips.append({"ip": ip, "error": str(e)})
            print(f"[!] Erreur lors du blocage de {ip}: {e}")
    
    # Enregistrer les résultats
    containment_results = {
        "blocked_ips": blocked_ips,
        "failed_ips": failed_ips,
        "os_type": os_type
    }
    log_event(session, "NETWORK_CONTAINMENT", containment_results)
    
    # Afficher un résumé
    if blocked_ips:
        print(f"[+] {len(blocked_ips)} IPs bloquées avec succès")
    if failed_ips:
        print(f"[!] {len(failed_ips)} IPs n'ont pas pu être bloquées")
    
    return containment_results

def disable_network_interface(session, interface_name):
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
