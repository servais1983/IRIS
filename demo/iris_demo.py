#!/usr/bin/env python3

import os
import sys
import time
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import print as rprint

console = Console()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def show_banner():
    banner = """
    ██╗██████╗ ██╗███████╗
    ██║██╔══██╗██║██╔════╝
    ██║██████╔╝██║███████╗
    ██║██╔══██╗██║╚════██║
    ██║██║  ██║██║███████║
    ╚═╝╚═╝  ╚═╝╚═╝╚══════╝
    """
    console.print(Panel(banner, style="bold blue"))
    console.print("[bold yellow]IRIS - Incident Response Intelligent System[/bold yellow]")
    console.print("[italic]Version Démo - Pour présentation uniquement[/italic]\n")

def simulate_analysis():
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task1 = progress.add_task("[cyan]Analyse mémoire en cours...", total=100)
        for i in range(100):
            time.sleep(0.05)
            progress.update(task1, advance=1)

        task2 = progress.add_task("[green]Collecte des artefacts...", total=100)
        for i in range(100):
            time.sleep(0.03)
            progress.update(task2, advance=1)

        task3 = progress.add_task("[yellow]Vérification des menaces...", total=100)
        for i in range(100):
            time.sleep(0.02)
            progress.update(task3, advance=1)

def show_results():
    table = Table(title="Résultats de l'analyse")
    table.add_column("Type", style="cyan")
    table.add_column("Détails", style="green")
    table.add_column("Statut", style="yellow")

    table.add_row(
        "Processus suspects",
        "3 processus détectés",
        "⚠️ Attention"
    )
    table.add_row(
        "Artefacts système",
        "12 fichiers collectés",
        "✅ OK"
    )
    table.add_row(
        "Menaces détectées",
        "1 IP malveillante",
        "❌ Critique"
    )
    table.add_row(
        "Rapport",
        "Généré avec succès",
        "✅ OK"
    )

    console.print(table)

def main_menu():
    while True:
        clear_screen()
        show_banner()
        
        console.print("\n[bold]Menu Principal[/bold]")
        console.print("1. Lancer une analyse complète")
        console.print("2. Voir les fonctionnalités")
        console.print("3. À propos")
        console.print("4. Quitter")
        
        choice = Prompt.ask("\nVotre choix", choices=["1", "2", "3", "4"])
        
        if choice == "1":
            clear_screen()
            show_banner()
            simulate_analysis()
            show_results()
            input("\nAppuyez sur Entrée pour continuer...")
        
        elif choice == "2":
            clear_screen()
            show_banner()
            console.print("\n[bold]Fonctionnalités principales :[/bold]")
            console.print("• Analyse mémoire forensique")
            console.print("• Collecte d'artefacts système")
            console.print("• Détection de menaces")
            console.print("• Génération de rapports")
            console.print("• Monitoring en temps réel")
            console.print("• Gestion de la sécurité")
            input("\nAppuyez sur Entrée pour continuer...")
        
        elif choice == "3":
            clear_screen()
            show_banner()
            console.print("\n[bold]À propos d'IRIS[/bold]")
            console.print("IRIS est un outil d'incident response avancé")
            console.print("qui permet d'analyser et de répondre aux incidents")
            console.print("de sécurité de manière efficace et automatisée.")
            input("\nAppuyez sur Entrée pour continuer...")
        
        elif choice == "4":
            if Confirm.ask("Voulez-vous vraiment quitter ?"):
                clear_screen()
                console.print("[bold green]Au revoir ![/bold green]")
                sys.exit(0)

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        clear_screen()
        console.print("[bold green]Au revoir ![/bold green]")
        sys.exit(0) 