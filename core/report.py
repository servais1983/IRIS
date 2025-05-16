import os
import json
import time
import datetime
import markdown
import platform
import matplotlib.pyplot as plt
from core.utils import log_event

def generate_report(session, quick=False):
    """
    Génère un rapport complet de l'investigation.
    
    Args:
        session (str): Identifiant de la session d'investigation
        quick (bool): Si True, génère un rapport simplifié
    """
    print("[*] Génération de rapport...")
    
    # Chemin du fichier journal et du rapport
    log_path = f"evidence/{session}/iris_log.json"
    report_md_path = f"evidence/{session}/report.md"
    report_html_path = f"evidence/{session}/report.html"
    timeline_path = f"evidence/{session}/timeline.png"
    
    # Vérifier que le journal existe
    if not os.path.exists(log_path):
        error_msg = f"Fichier journal introuvable: {log_path}"
        print(f"[!] {error_msg}")
        log_event(session, "REPORT_ERROR", {"error": error_msg})
        return False
    
    # Lire le journal pour en extraire les événements
    events = []
    with open(log_path, 'r') as f:
        for line in f:
            try:
                event = json.loads(line.strip())
                events.append(event)
            except json.JSONDecodeError:
                print(f"[!] Ligne JSON invalide dans le journal: {line.strip()}")
    
    # Afficher un message d'erreur si aucun événement n'a été trouvé
    if not events:
        error_msg = "Aucun événement trouvé dans le journal"
        print(f"[!] {error_msg}")
        log_event(session, "REPORT_ERROR", {"error": error_msg})
        return False
    
    # Préparer le contenu du rapport
    report_content = []
    
    # --- En-tête du rapport ---
    report_content.append("# Rapport d'Investigation IRIS\n")
    
    # Horodatage et informations générales
    start_time = None
    end_time = None
    investigation_mode = None
    
    for event in events:
        if event['type'] == "INVESTIGATION_START":
            start_time = event['timestamp']
            investigation_mode = event['data'].get('mode', 'unknown')
        elif event['type'] == "INVESTIGATION_END":
            end_time = event['timestamp']
    
    report_content.append(f"## Informations générales\n")
    report_content.append(f"- **ID d'investigation:** {session}")
    report_content.append(f"- **Mode d'investigation:** {investigation_mode}")
    report_content.append(f"- **Début:** {start_time}")
    report_content.append(f"- **Fin:** {end_time or 'En cours'}")
    report_content.append(f"- **Système:** {platform.system()} {platform.release()}")
    report_content.append(f"- **Rapport généré le:** {datetime.datetime.now().isoformat()}")
    report_content.append("\n")
    
    # --- Résumé des résultats ---
    report_content.append("## Résumé des résultats\n")
    
    # Résumé de l'analyse mémoire
    for event in events:
        if event['type'] == "MEMORY_ANALYSIS":
            total_procs = event['data'].get('total_processes', 0)
            suspicious_procs = event['data'].get('suspicious_processes', 0)
            report_content.append(f"- **Processus analysés:** {total_procs}")
            report_content.append(f"- **Processus suspects:** {suspicious_procs}")
            
            if suspicious_procs > 0 and not quick:
                report_content.append("\n### Processus suspects détectés\n")
                report_content.append("| PID | Nom | Utilisateur |")
                report_content.append("|-----|-----|------------|")
                
                for proc in event['data'].get('details', []):
                    if proc.get('suspicious', False):
                        pid = proc.get('pid', 'N/A')
                        name = proc.get('name', 'N/A')
                        user = proc.get('username', 'N/A')
                        report_content.append(f"| {pid} | {name} | {user} |")
    
    # Résumé de la collecte d'artefacts
    for event in events:
        if event['type'] == "ARTIFACT_COLLECTION_SUMMARY":
            collected = event['data'].get('collected', 0)
            failed = event['data'].get('failed', 0)
            system = event['data'].get('system', 'unknown')
            report_content.append(f"- **Artefacts collectés:** {collected}")
            report_content.append(f"- **Échecs de collecte:** {failed}")
    
    # Résumé des containments réseau
    for event in events:
        if event['type'] == "NETWORK_CONTAINMENT":
            blocked = len(event['data'].get('blocked_ips', []))
            failed = len(event['data'].get('failed_ips', []))
            report_content.append(f"- **IPs bloquées:** {blocked}")
            
            if blocked > 0:
                ips = ", ".join(event['data'].get('blocked_ips', []))
                report_content.append(f"  - {ips}")
    
    # Résumé des vérifications Threat Intel
    intel_hits = {}
    for event in events:
        if event['type'] == "THREAT_INTEL":
            for indicator, results in event['data'].items():
                for source, result in results.items():
                    if result.get('found', False):
                        intel_hits[indicator] = intel_hits.get(indicator, []) + [source]
    
    if intel_hits:
        report_content.append("- **Indicateurs malveillants confirmés:**")
        for indicator, sources in intel_hits.items():
            report_content.append(f"  - {indicator} (Sources: {', '.join(sources)})")
    
    report_content.append("\n")
    
    # --- Timeline des événements ---
    # Créer une chronologie visuelle si matplotlib est disponible
    try:
        # Extraire les événements significatifs pour la timeline
        timeline_events = []
        for event in events:
            if event['type'] in ["INVESTIGATION_START", "MEMORY_ANALYSIS", 
                                "ARTIFACT_COLLECTION_SUMMARY", "NETWORK_CONTAINMENT", 
                                "THREAT_INTEL", "INVESTIGATION_END"]:
                event_time = datetime.datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                timeline_events.append((event_time, event['type']))
        
        if timeline_events and not quick:
            # Créer un graphique de chronologie
            fig, ax = plt.figure(figsize=(10, 6)), plt.gca()
            
            # Préparer les données pour le graphique
            times = [e[0] for e in timeline_events]
            types = [e[1] for e in timeline_events]
            
            # Créer le graphique
            ax.scatter(times, types, s=100, alpha=0.7)
            ax.grid(True)
            
            # Formatage
            plt.title("Chronologie de l'investigation")
            plt.xlabel("Temps")
            plt.ylabel("Événement")
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            # Sauvegarder le graphique
            plt.savefig(timeline_path)
            plt.close()
            
            report_content.append(f"## Chronologie de l'investigation\n")
            report_content.append(f"![Chronologie]({os.path.basename(timeline_path)})\n")
    except Exception as e:
        print(f"[!] Erreur lors de la création de la chronologie: {e}")
    
    # --- Section détaillée ---
    if not quick:
        report_content.append("## Détails de l'investigation\n")
        
        # Ajouter des sections détaillées pour chaque type d'analyse
        # Cette partie pourrait être étendue avec plus de détails dans une implémentation complète
        
        # Threat Intelligence détaillée
        report_content.append("### Résultats Threat Intelligence\n")
        for event in events:
            if event['type'] == "THREAT_INTEL":
                for indicator, results in event['data'].items():
                    report_content.append(f"#### Indicateur: {indicator}\n")
                    
                    for source, result in results.items():
                        report_content.append(f"**Source: {source}**\n")
                        
                        if "error" in result:
                            report_content.append(f"- Erreur: {result['error']}")
                        elif result.get('found', False):
                            # Détails spécifiques selon la source
                            if source == "AlienVault OTX":
                                report_content.append(f"- Premiers signalements: {result.get('first_seen', 'N/A')}")
                                report_content.append(f"- Derniers signalements: {result.get('last_seen', 'N/A')}")
                                report_content.append(f"- Score de menace: {result.get('threat_score', 'N/A')}")
                                
                                if 'categories' in result:
                                    cats = ', '.join(result['categories']) if result['categories'] else 'Aucune'
                                    report_content.append(f"- Catégories: {cats}")
                            
                            elif source == "MISP":
                                report_content.append(f"- Nombre d'événements: {result.get('events_count', 0)}")
                                report_content.append(f"- Niveau de menace: {result.get('threat_level', 'N/A')}")
                        else:
                            report_content.append("- Non trouvé dans cette source")
                        
                        report_content.append("\n")
    
    # --- Recommandations ---
    report_content.append("## Recommandations\n")
    
    # Générer des recommandations automatiques basées sur les résultats
    if intel_hits:
        report_content.append("- **Haute priorité:** Des indicateurs malveillants confirmés ont été détectés. Une investigation approfondie est nécessaire.")
    
    suspicious_procs_found = False
    for event in events:
        if event['type'] == "MEMORY_ANALYSIS" and event['data'].get('suspicious_processes', 0) > 0:
            suspicious_procs_found = True
    
    if suspicious_procs_found:
        report_content.append("- **Moyenne priorité:** Des processus suspects ont été identifiés. Analyser manuellement ces processus pour confirmer leur légitimité.")
    
    report_content.append("- **Générale:** Effectuer une analyse anti-malware complète du système.")
    report_content.append("- **Générale:** Vérifier les journaux d'authentification pour détecter d'éventuelles activités suspectes.")
    report_content.append("\n")
    
    # --- Écrire le rapport ---
    with open(report_md_path, 'w') as f:
        f.write('\n'.join(report_content))
    
    # Générer le HTML si la bibliothèque markdown est disponible
    try:
        with open(report_md_path, 'r') as f:
            md_content = f.read()
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Rapport d'Investigation IRIS - {session}</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; padding: 20px; max-width: 1200px; margin: 0 auto; }}
                h1, h2, h3 {{ color: #2c3e50; }}
                table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                img {{ max-width: 100%; }}
                .header {{ background-color: #34495e; color: white; padding: 10px; text-align: center; }}
                .footer {{ margin-top: 30px; text-align: center; font-size: 0.8em; color: #7f8c8d; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>IRIS - Rapport d'Investigation</h1>
                <p>ID: {session}</p>
            </div>
            
            {markdown.markdown(md_content)}
            
            <div class="footer">
                <p>Généré par IRIS - Incident Response Intelligent System</p>
            </div>
        </body>
        </html>
        """
        
        with open(report_html_path, 'w') as f:
            f.write(html_content)
        
        print(f"[+] Rapport HTML généré: {report_html_path}")
        
    except Exception as e:
        print(f"[!] Erreur lors de la génération du rapport HTML: {e}")
    
    # Enregistrer l'action
    log_event(session, "REPORT_GENERATED", {
        "markdown_path": report_md_path,
        "html_path": report_html_path,
        "timeline_path": timeline_path if os.path.exists(timeline_path) else None
    })
    
    print(f"[+] Rapport généré: {report_md_path}")
    return True
