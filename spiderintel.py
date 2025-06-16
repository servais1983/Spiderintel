import os
import sys
import argparse
import subprocess
import requests
import json
import sqlite3
import whois  # Ajout de l'import python-whois
from termcolor import cprint
from datetime import datetime
from rich.console import Console
from rich.progress import track, Progress

console = Console()

# ---- CONFIG ----
TOOLS = {
    "whois": "/usr/bin/whois",
    "dnsenum": "/usr/bin/dnsenum",
    "theHarvester": "/usr/bin/theHarvester",
    "whatweb": "/usr/bin/whatweb",
    "photon": "/usr/bin/photon"
}

DB_PATH = "spiderintel.db"
SHODAN_API_KEY = ""  # Nécessite un abonnement payant Shodan

# ---- FUNCTIONS ----
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT,
                report_path TEXT,
                created_at TEXT
            )
        ''')
        conn.commit()


def store_report_metadata(domain, report_path):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute('INSERT INTO reports (domain, report_path, created_at) VALUES (?, ?, ?)',
                  (domain, report_path, datetime.now().isoformat()))
        conn.commit()


def check_dependencies():
    """Vérifie et installe les dépendances nécessaires"""
    missing_tools = []
    missing_python_packages = []
    
    # Vérification des outils système
    for tool, path in TOOLS.items():
        if not os.path.exists(path):
            missing_tools.append(tool)
    
    # Vérification des packages Python
    try:
        import tld
    except ImportError:
        missing_python_packages.append('tld')
    
    if missing_tools or missing_python_packages:
        console.print("\n[bold red]Dépendances manquantes détectées :[/]")
        if missing_tools:
            console.print("\n[bold yellow]Outils système manquants :[/]")
            for tool in missing_tools:
                console.print(f"  - {tool}")
            console.print("\nPour installer les outils manquants sur Linux, exécutez :")
            console.print("[cyan]sudo apt update && sudo apt install -y whois dnsenum theharvester whatweb photon[/]")
        
        if missing_python_packages:
            console.print("\n[bold yellow]Packages Python manquants :[/]")
            for package in missing_python_packages:
                console.print(f"  - {package}")
            console.print("\nPour installer les packages Python manquants, exécutez :")
            console.print("[cyan]pip install tld[/]")
        
        return False
    return True


def run_cmd(cmd, output_file):
    try:
        console.print(f"\n[bold cyan]Exécution de {cmd[0]}...[/]")
        with open(output_file, 'w', encoding='utf-8') as f:
            result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)
            if result.returncode != 0:
                console.print(f"[bold red]Erreur lors de l'exécution de {cmd[0]} :[/]")
                console.print(f"[yellow]{result.stderr}[/]")
                return False
            
            # Vérification du contenu du fichier
            with open(output_file, 'r', encoding='utf-8') as f:
                content = f.read()
                if content.strip():
                    console.print(f"[green]Résultats de {cmd[0]} sauvegardés dans {output_file}[/]")
                    console.print(f"[white]{content[:500]}...[/]")
                else:
                    console.print(f"[yellow]Aucun résultat pour {cmd[0]}[/]")
                    # Écrire un message d'erreur dans le fichier
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(f"Aucun résultat trouvé pour {cmd[0]}\n")
                        f.write(f"Commande exécutée : {' '.join(cmd)}\n")
                        f.write(f"Code de retour : {result.returncode}\n")
                        if result.stderr:
                            f.write(f"Erreur : {result.stderr}\n")
            return True
    except FileNotFoundError:
        console.print(f"[bold red]Erreur :[/] L'outil {cmd[0]} n'est pas installé. Veuillez l'installer avec :")
        console.print(f"[cyan]sudo apt install {cmd[0]}[/]")
        return False
    except Exception as e:
        console.print(f"[bold red]Erreur :[/] {str(e)}")
        return False


def fetch_crtsh(domain, output_file):
    console.print("\n[bold cyan]Recherche des certificats SSL sur crt.sh...[/]")
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        r = requests.get(url)
        if r.status_code != 200:
            console.print(f"[bold red]Erreur lors de la requête crt.sh :[/] {r.status_code}")
            return False
            
        data = r.json()
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
            
        # Afficher un résumé des certificats
        if data:
            console.print("[green]Certificats SSL trouvés :[/]")
            unique_domains = set()
            for cert in data:
                if 'name_value' in cert:
                    unique_domains.add(cert['name_value'])
            for domain in sorted(unique_domains):
                console.print(f"[white]- {domain}[/]")
        else:
            console.print("[yellow]Aucun certificat SSL trouvé[/]")
            
        console.print("[green]Résultats crt.sh sauvegardés.[/]")
        return True
    except Exception as e:
        console.print(f"[red]Erreur lors de la recherche crt.sh : {e}[/]")
        return False


def fetch_shodan_info(domain, output_file):
    console.print("\n[bold yellow]Note :[/] L'API Shodan nécessite un abonnement payant.")
    console.print("[yellow]Pour utiliser Shodan, vous devez :[/]")
    console.print("1. Créer un compte sur https://account.shodan.io/")
    console.print("2. Souscrire à un abonnement payant")
    console.print("3. Configurer votre clé API dans le fichier spiderintel.py")
    return False


def fetch_whois_info(domain, output_file):
    """Récupère les informations whois en utilisant python-whois"""
    try:
        console.print(f"\n[bold cyan]Recherche des informations WHOIS pour {domain}...[/]")
        w = whois.whois(domain)
        
        # Écriture des résultats dans le fichier
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"Domain Name: {domain}\n")
            f.write(f"Registrar: {w.registrar}\n")
            f.write(f"Creation Date: {w.creation_date}\n")
            f.write(f"Expiration Date: {w.expiration_date}\n")
            f.write(f"Name Servers: {w.name_servers}\n")
            f.write(f"Status: {w.status}\n")
            f.write(f"Emails: {w.emails}\n")
            f.write(f"Name: {w.name}\n")
            f.write(f"Organization: {w.org}\n")
            f.write(f"Address: {w.address}\n")
            f.write(f"City: {w.city}\n")
            f.write(f"State: {w.state}\n")
            f.write(f"Country: {w.country}\n")
            f.write(f"Zipcode: {w.zipcode}\n")
        
        # Affichage des résultats
        console.print("[green]Informations WHOIS trouvées :[/]")
        console.print(f"[white]Registrar: {w.registrar}[/]")
        console.print(f"[white]Creation Date: {w.creation_date}[/]")
        console.print(f"[white]Expiration Date: {w.expiration_date}[/]")
        console.print(f"[white]Name Servers: {w.name_servers}[/]")
        
        return True
    except Exception as e:
        console.print(f"[bold red]Erreur lors de la recherche WHOIS : {str(e)}[/]")
        return False


def clean_ansi_codes(text):
    """Nettoie les codes ANSI du texte"""
    import re
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


def generate_report(output_dir, domain):
    """Génère un rapport complet au format Markdown et HTML"""
    try:
        report_path = os.path.join(output_dir, "report.md")
        html_path = os.path.join(output_dir, "report.html")
        
        console.print("\n[bold cyan]Génération du rapport...[/]")
        
        # Génération du rapport Markdown
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(f"# Rapport OSINT - {domain}\n\n")
            f.write(f"Date de génération : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Informations Whois
            whois_path = os.path.join(output_dir, "whois.txt")
            if os.path.exists(whois_path):
                f.write("## Informations Whois\n\n")
                with open(whois_path, "r", encoding="utf-8") as whois_file:
                    f.write("```\n")
                    f.write(whois_file.read())
                    f.write("\n```\n\n")
            
            # Résultats DNS
            dns_path = os.path.join(output_dir, "dnsenum.txt")
            if os.path.exists(dns_path):
                f.write("## Résultats DNS\n\n")
                with open(dns_path, "r", encoding="utf-8") as dns_file:
                    content = clean_ansi_codes(dns_file.read())
                    f.write("```\n")
                    f.write(content)
                    f.write("\n```\n\n")
            
            # Résultats TheHarvester
            harvester_path = os.path.join(output_dir, "harvester.txt")
            if os.path.exists(harvester_path):
                f.write("## Résultats TheHarvester\n\n")
                with open(harvester_path, "r", encoding="utf-8") as harvester_file:
                    content = clean_ansi_codes(harvester_file.read())
                    f.write("```\n")
                    f.write(content)
                    f.write("\n```\n\n")
            
            # Informations WhatWeb
            whatweb_path = os.path.join(output_dir, "whatweb.txt")
            if os.path.exists(whatweb_path):
                f.write("## Informations WhatWeb\n\n")
                with open(whatweb_path, "r", encoding="utf-8") as whatweb_file:
                    content = clean_ansi_codes(whatweb_file.read())
                    f.write("```\n")
                    f.write(content)
                    f.write("\n```\n\n")
            
            # Résultats Photon
            photon_dir = os.path.join(output_dir, "photon")
            if os.path.exists(photon_dir):
                f.write("## Résultats Photon\n\n")
                # URLs trouvées
                urls_file = os.path.join(photon_dir, "urls.txt")
                if os.path.exists(urls_file):
                    f.write("### URLs trouvées\n\n")
                    with open(urls_file, "r", encoding="utf-8") as urls_file:
                        f.write("```\n")
                        f.write(urls_file.read())
                        f.write("\n```\n\n")
                
                # Fichiers trouvés
                files_file = os.path.join(photon_dir, "files.txt")
                if os.path.exists(files_file):
                    f.write("### Fichiers trouvés\n\n")
                    with open(files_file, "r", encoding="utf-8") as files_file:
                        f.write("```\n")
                        f.write(files_file.read())
                        f.write("\n```\n\n")
            
            # Certificats SSL
            crtsh_path = os.path.join(output_dir, "crtsh.json")
            if os.path.exists(crtsh_path):
                f.write("## Certificats SSL\n\n")
                with open(crtsh_path, "r", encoding="utf-8") as crtsh_file:
                    crtsh_data = json.load(crtsh_file)
                    unique_domains = set()
                    for cert in crtsh_data:
                        if 'name_value' in cert:
                            unique_domains.add(cert['name_value'])
                    for domain in sorted(unique_domains):
                        f.write(f"- {domain}\n")
                f.write("\n")
            
            # Informations Shodan
            shodan_path = os.path.join(output_dir, "shodan.json")
            if os.path.exists(shodan_path):
                f.write("## Informations Shodan\n\n")
                with open(shodan_path, "r", encoding="utf-8") as shodan_file:
                    shodan_data = json.load(shodan_file)
                    if shodan_data:
                        f.write("```json\n")
                        f.write(json.dumps(shodan_data, indent=2))
                        f.write("\n```\n\n")
                    else:
                        f.write("Aucune information disponible (Abonnement Shodan requis)\n\n")
        
        console.print("[green]Rapport Markdown généré avec succès.[/]")
        
        # Génération du rapport HTML
        if os.path.exists("/usr/bin/pandoc"):
            try:
                # Création du fichier CSS temporaire
                css_path = os.path.join(output_dir, "style.css")
                with open(css_path, "w", encoding="utf-8") as css_file:
                    css_file.write("""
                    body {
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        line-height: 1.6;
                        color: #333;
                        max-width: 1200px;
                        margin: 0 auto;
                        padding: 20px;
                        background-color: #f5f5f5;
                    }
                    h1 {
                        color: #2c3e50;
                        text-align: center;
                        padding: 20px;
                        background-color: #fff;
                        border-radius: 8px;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                        margin-bottom: 30px;
                    }
                    h2 {
                        color: #3498db;
                        border-bottom: 2px solid #3498db;
                        padding-bottom: 10px;
                        margin-top: 40px;
                    }
                    pre {
                        background-color: #2c3e50;
                        color: #ecf0f1;
                        padding: 15px;
                        border-radius: 5px;
                        overflow-x: auto;
                    }
                    code {
                        font-family: 'Consolas', 'Monaco', monospace;
                    }
                    .metadata {
                        background-color: #fff;
                        padding: 15px;
                        border-radius: 8px;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                        margin-bottom: 30px;
                    }
                    .section {
                        background-color: #fff;
                        padding: 20px;
                        border-radius: 8px;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                        margin-bottom: 20px;
                    }
                    ul {
                        list-style-type: none;
                        padding: 0;
                    }
                    li {
                        padding: 8px 0;
                        border-bottom: 1px solid #eee;
                    }
                    li:last-child {
                        border-bottom: none;
                    }
                    .json-content {
                        background-color: #2c3e50;
                        color: #ecf0f1;
                        padding: 15px;
                        border-radius: 5px;
                        overflow-x: auto;
                    }
                    """)
                
                subprocess.run([
                    "pandoc",
                    report_path,
                    "-o", html_path,
                    "--standalone",
                    "--css", css_path,
                    "--metadata", "title=Rapport OSINT",
                    "--toc",
                    "--toc-depth=2"
                ], timeout=30)
                
                # Nettoyage du fichier CSS temporaire
                os.remove(css_path)
                
                console.print("[green]Rapport HTML généré avec succès.[/]")
            except Exception as e:
                console.print(f"[yellow]Erreur lors de la génération du rapport HTML : {str(e)}[/]")
        else:
            console.print("[yellow]Pandoc non installé, rapport HTML non généré.[/]")
        
        return True
    except Exception as e:
        console.print(f"[bold red]Erreur lors de la génération du rapport : {str(e)}[/]")
        return False


def banner():
    console.print("""
[bold red]╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗[/]
[bold red]║                                                                                                      ║[/]
[bold red]║  ███████╗██████╗ ██╗██████╗ ███████╗██████╗ ██╗███╗   ██╗████████╗███████╗██╗     ║[/]
[bold red]║  ██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔══██╗██║████╗  ██║╚══██╔══╝██╔════╝██║     ║[/]
[bold red]║  ███████╗██████╔╝██║██║  ██║█████╗  ██████╔╝██║██╔██╗ ██║   ██║   █████╗  ██║     ║[/]
[bold red]║  ╚════██║██╔═══╝ ██║██║  ██║██╔══╝  ██╔══██╗██║██║╚██╗██║   ██║   ██╔══╝  ██║     ║[/]
[bold red]║  ███████║██║     ██║██████╔╝███████╗██║  ██║██║██║ ╚████║   ██║   ███████╗███████╗║[/]
[bold red]║  ╚══════╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝║[/]
[bold red]║                                                                                                      ║[/]
[bold red]╚══════════════════════════════════════════════════════════════════════════════════════════════════════╝[/]
    """, justify="center")
    console.print("\n[bold yellow]Développé par:[/] [cyan]Votre Nom[/]")
    console.print("[bold yellow]Description:[/] [cyan]Outil de collecte d'informations OSINT automatisé[/]\n")

# ---- MAIN ----
def main():
    try:
        if len(sys.argv) != 2:
            console.print("[bold red]Usage:[/] python3 spiderintel.py <domain>")
            sys.exit(1)
        
        domain = sys.argv[1]
        banner()
        
        # Vérification des dépendances avant de commencer
        if not check_dependencies():
            console.print("\n[bold red]Veuillez installer les dépendances manquantes avant de continuer.[/]")
            sys.exit(1)
        
        console.print(f"\n[bold green][{datetime.now().strftime('%H:%M:%S')}][/] Démarrage de l'analyse OSINT sur : {domain}")
        
        # Création du dossier de sortie
        output_dir = f"osint_{domain}_{datetime.now().strftime('%Y-%m-%d_%H-%M')}"
        os.makedirs(output_dir, exist_ok=True)
        
        # Liste des tâches à exécuter
        tasks = [
            (fetch_whois_info, domain, os.path.join(output_dir, "whois.txt")),
            (run_cmd, [TOOLS["dnsenum"], domain], os.path.join(output_dir, "dnsenum.txt")),
            (run_cmd, [TOOLS["theHarvester"], "-d", domain, "-b", "all"], os.path.join(output_dir, "harvester.txt")),
            (run_cmd, [TOOLS["whatweb"], domain], os.path.join(output_dir, "whatweb.txt")),
            (run_cmd, [TOOLS["photon"], "-u", f"http://{domain}", "-o", os.path.join(output_dir, "photon")], os.path.join(output_dir, "photon_log.txt")),
            (fetch_crtsh, domain, os.path.join(output_dir, "crtsh.json")),
            (fetch_shodan_info, domain, os.path.join(output_dir, "shodan.json"))
        ]
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Collecte des données...", total=len(tasks))
            
            for func, *args in tasks:
                try:
                    console.print(f"\n[bold cyan]Exécution de {func.__name__}...[/]")
                    result = func(*args)
                    if not result:
                        console.print(f"[bold yellow]Attention : {func.__name__} n'a pas retourné de résultats[/]")
                except KeyboardInterrupt:
                    console.print("\n[bold yellow]Analyse interrompue par l'utilisateur.[/]")
                    return 1
                except Exception as e:
                    console.print(f"[bold red]Erreur lors de l'exécution de {func.__name__}:[/] {str(e)}")
                progress.advance(task)
        
        # Vérification des fichiers générés
        console.print("\n[bold cyan]Vérification des fichiers générés :[/]")
        for file in os.listdir(output_dir):
            file_path = os.path.join(output_dir, file)
            if os.path.isfile(file_path):
                size = os.path.getsize(file_path)
                console.print(f"[white]{file}: {size} octets[/]")
        
        # Génération du rapport
        if generate_report(output_dir, domain):
            console.print(f"\n[bold green]Analyse terminée. Rapport disponible dans le dossier : {output_dir}[/]")
            return 0
        else:
            console.print("\n[bold yellow]Analyse terminée avec des erreurs. Vérifiez le rapport pour plus de détails.[/]")
            return 1
            
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Programme interrompu par l'utilisateur.[/]")
        return 1
    except Exception as e:
        console.print(f"\n[bold red]Erreur inattendue : {str(e)}[/]")
        return 1


if __name__ == "__main__":
    sys.exit(main()) 