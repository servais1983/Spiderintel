#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SpiderIntel - Outil d'OSINT et d'analyse de vulnérabilités automatisé
Auteur: Professional Security Tools
Version: 2.0.0
Licence: MIT
"""

import os
import sys
import argparse
import subprocess
import requests
import json
import sqlite3
import whois
import configparser
import shutil
import concurrent.futures
import re
import networkx as nx
import matplotlib.pyplot as plt
from collections import defaultdict
from termcolor import cprint
from datetime import datetime
from pathlib import Path
import tldextract
from tqdm import tqdm
import urllib3
import time
import psutil
import xml.etree.ElementTree as ET
import dns.resolver
from bs4 import BeautifulSoup
import threading
import queue
import hashlib
import socket
from dataclasses import dataclass
from typing import Dict, List, Set, Optional, Any
import logging
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

# Désactiver les avertissements SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Logo ASCII de SpiderIntel
SPIDERINTEL_LOGO = """
███████╗██████╗ ██╗██████╗ ███████╗██████╗     ██╗███╗   ██╗████████╗███████╗██╗     
██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔══██╗    ██║████╗  ██║╚══██╔══╝██╔════╝██║     
███████╗██████╔╝██║██║  ██║█████╗  ██████╔╝    ██║██╔██╗ ██║   ██║   █████╗  ██║     
╚════██║██╔═══╝ ██║██║  ██║██╔══╝  ██╔══██╗    ██║██║╚██╗██║   ██║   ██╔══╝  ██║     
███████║██║     ██║██████╔╝███████╗██║  ██║    ██║██║ ╚████║   ██║   ███████╗███████╗
╚══════╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝    ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝
"""

def print_banner():
    """Affiche la bannière de SpiderIntel"""
    print("\033[1;36m" + SPIDERINTEL_LOGO + "\033[0m")
    print("\033[1;33m" + "=" * 80 + "\033[0m")
    print("\033[1;32m" + "SpiderIntel v2.0.0 - Outil d'analyse de sécurité professionnel" + "\033[0m")
    print("\033[1;32m" + "OSINT + Scan de vulnérabilités + Exploitation" + "\033[0m")
    print("\033[1;33m" + "=" * 80 + "\033[0m\n")

# Configuration du logging
def setup_logging():
    """Configure le système de logging"""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / 'spiderintel.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

logger = setup_logging()

@dataclass
class VulnerabilityResult:
    """Structure pour les résultats de vulnérabilités"""
    name: str
    severity: str
    description: str
    cvss_score: float
    cve_id: str = ""
    exploit_available: bool = False
    exploit_code: str = ""
    mitigation: str = ""
    references: List[str] = None

    def __post_init__(self):
        if self.references is None:
            self.references = []

@dataclass
class OSINTResult:
    """Structure pour les résultats OSINT"""
    subdomains: Set[str]
    emails: Set[str]
    ips: Set[str]
    technologies: Set[str]
    ports: Dict[str, List[int]]
    certificates: Dict[str, Any]
    social_media: Set[str]
    
    def __post_init__(self):
        for field in ['subdomains', 'emails', 'ips', 'technologies', 'social_media']:
            if not hasattr(self, field):
                setattr(self, field, set())
        if not hasattr(self, 'ports'):
            self.ports = {}
        if not hasattr(self, 'certificates'):
            self.certificates = {}

class SecurityValidator:
    """Classe pour la validation de sécurité des inputs"""
    
    @staticmethod
    def validate_domain(domain: str) -> bool:
        """Valide le format du domaine"""
        if not domain or len(domain) > 253:
            return False
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.match(pattern, domain))
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Valide le format de l'IP"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, ip):
            return False
        return all(0 <= int(x) <= 255 for x in ip.split('.'))
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Valide le format de l'email"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

class SecureHTTPSession:
    """Session HTTP sécurisée avec gestion des erreurs"""
    
    def __init__(self, timeout=10, max_retries=2):
        self.session = requests.Session()
        self.session.verify = False  # Désactive la vérification SSL
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_strategy = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504]
        )
        self.session.mount('http://', HTTPAdapter(max_retries=self.retry_strategy))
        self.session.mount('https://', HTTPAdapter(max_retries=self.retry_strategy))
        
        # Supprime les avertissements SSL
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Requête GET avec gestion des erreurs"""
        try:
            # Ajoute le protocole si manquant
            if not url.startswith(('http://', 'https://')):
                url = f"https://{url}"

            # Extrait le hostname pour la résolution DNS
            from urllib.parse import urlparse
            hostname = urlparse(url).hostname or ''

            # Vérifie d'abord la résolution DNS
            try:
                socket.gethostbyname(hostname)
            except socket.gaierror:
                logger.warning(f"⚠ Impossible de résoudre le nom de domaine: {hostname}")
                return None

            response = self.session.get(url, timeout=self.timeout, **kwargs)
            return response
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"⚠ Erreur lors de la requête vers {url}: {str(e)}")
            return None

class OSINTScanner:
    """Scanner OSINT avec corrections"""
    
    def __init__(self, domain: str):
        self.domain = self.clean_domain(domain)
        self.root_domain = self.get_root_domain(domain)
        self.http_session = SecureHTTPSession()
        self.validator = SecurityValidator()
        self.results = OSINTResult(
            subdomains=set(),
            emails=set(),
            ips=set(),
            technologies=set(),
            ports={},
            certificates={},
            social_media=set()
        )
    
    def clean_domain(self, domain: str) -> str:
        """Nettoie et normalise le domaine"""
        domain = domain.replace("http://", "").replace("https://", "")
        domain = domain.split("/")[0].split(":")[0]
        return domain.lower()
    
    def get_root_domain(self, domain: str) -> str:
        """Extrait le domaine racine"""
        extracted = tldextract.extract(domain)
        return f"{extracted.domain}.{extracted.suffix}"
    
    def scan_crtsh(self) -> None:
        """Scan des certificats SSL via crt.sh"""
        logger.info("🔍 Scan des certificats SSL (crt.sh)...")
        try:
            url = f"https://crt.sh/?q={self.root_domain}&output=json"
            response = self.http_session.get(url)
            
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    for entry in data:
                        if 'name_value' in entry:
                            subdomains = entry['name_value'].split('\n')
                            for subdomain in subdomains:
                                subdomain = subdomain.strip().replace('*.', '')
                                if self.validator.validate_domain(subdomain):
                                    self.results.subdomains.add(subdomain)
                                    
                                    # Stocker les informations de certificat
                                    if subdomain not in self.results.certificates:
                                        self.results.certificates[subdomain] = {
                                            'issuer': entry.get('issuer_name', ''),
                                            'not_before': entry.get('not_before', ''),
                                            'not_after': entry.get('not_after', ''),
                                            'serial_number': entry.get('serial_number', '')
                                        }
                    
                    logger.info(f"✅ crt.sh: {len(self.results.subdomains)} sous-domaines trouvés")
                except json.JSONDecodeError:
                    logger.error("❌ Erreur de décodage JSON crt.sh")
        except Exception as e:
            logger.error(f"❌ Erreur crt.sh: {e}")
    
    def scan_dns_enumeration(self) -> None:
        """Énumération DNS avancée"""
        logger.info("🔍 Énumération DNS...")
        
        # Liste des sous-domaines courants
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
            'blog', 'shop', 'vpn', 'secure', 'portal', 'app', 'mobile',
            'support', 'help', 'docs', 'cdn', 'static', 'assets', 'media',
            'images', 'upload', 'download', 'files', 'backup', 'old',
            'new', 'beta', 'alpha', 'demo', 'sandbox', 'internal',
            'intranet', 'extranet', 'remote', 'cloud', 'server',
            'db', 'database', 'sql', 'mysql', 'postgres', 'redis',
            'monitoring', 'status', 'health', 'metrics', 'logs'
        ]
        
        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{self.root_domain}"
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 10
                
                answers = resolver.resolve(full_domain, 'A')
                for answer in answers:
                    ip = str(answer)
                    if self.validator.validate_ip(ip):
                        self.results.subdomains.add(full_domain)
                        self.results.ips.add(ip)
                        if full_domain not in self.results.ports:
                            self.results.ports[full_domain] = []
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.Timeout, dns.exception.DNSException):
                pass

        # Utilisation de threads pour paralléliser
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            list(tqdm(
                executor.map(check_subdomain, common_subdomains),
                total=len(common_subdomains),
                desc="DNS enum"
            ))
        
        logger.info(f"✅ DNS: {len(self.results.subdomains)} sous-domaines trouvés")
    
    def scan_harvester(self) -> None:
        """Scan avec TheHarvester"""
        logger.info("🔍 Scan avec TheHarvester...")
        try:
            # Sources fiables pour TheHarvester
            sources = ["google", "bing", "yahoo", "duckduckgo", "crtsh"]
            
            for source in sources:
                try:
                    cmd = [
                        "theHarvester",
                        "-d", self.root_domain,
                        "-b", source,
                        "-l", "100",
                        "-f", f"/tmp/harvester_{source}_{self.root_domain}"
                    ]
                    
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=60
                    )
                    
                    if result.returncode == 0:
                        # Parser les résultats
                        output = result.stdout
                        
                        # Extraction des emails
                        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                        emails = re.findall(email_pattern, output)
                        for email in emails:
                            if self.validator.validate_email(email):
                                self.results.emails.add(email)
                        
                        # Extraction des sous-domaines
                        domain_pattern = rf'[a-zA-Z0-9.-]*\.{re.escape(self.root_domain)}'
                        subdomains = re.findall(domain_pattern, output)
                        for subdomain in subdomains:
                            if self.validator.validate_domain(subdomain):
                                self.results.subdomains.add(subdomain)
                        
                        # Extraction des IPs
                        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                        ips = re.findall(ip_pattern, output)
                        for ip in ips:
                            if self.validator.validate_ip(ip):
                                self.results.ips.add(ip)
                
                except subprocess.TimeoutExpired:
                    logger.warning(f"⚠️ Timeout TheHarvester pour {source}")
                except Exception as e:
                    logger.warning(f"⚠️ Erreur TheHarvester {source}: {e}")
            
            logger.info(f"✅ TheHarvester: {len(self.results.emails)} emails, {len(self.results.subdomains)} sous-domaines")
        
        except Exception as e:
            logger.error(f"❌ Erreur TheHarvester: {e}")
    
    def scan_whatweb(self) -> None:
        """Identification des technologies avec WhatWeb"""
        logger.info("🔍 Identification des technologies (WhatWeb)...")
        
        domains_to_scan = list(self.results.subdomains) + [self.domain]
        max_retries = 3
        retry_delay = 5
        timeout = 30
        
        for domain in domains_to_scan[:10]:  # Limiter pour éviter le spam
            for attempt in range(max_retries):
                try:
                    cmd = [
                        "whatweb",
                        "--no-errors",
                        "-a", "3",
                        "--max-redirects=3",
                        "--user-agent=SpiderIntel/2.0.0",
                        domain
                    ]
                    
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=timeout
                    )
                    
                    if result.returncode == 0:
                        output = result.stdout
                        
                        # Parser les technologies
                        tech_patterns = [
                            r'([A-Za-z0-9-]+)\[([^\]]+)\]',  # Format: Tech[version]
                            r'([A-Za-z0-9-]+)/([0-9.]+)',   # Format: Tech/version
                        ]
                        
                        for pattern in tech_patterns:
                            matches = re.finditer(pattern, output)
                            for match in matches:
                                tech = f"{match.group(1)}"
                                if len(tech) > 2:  # Éviter les faux positifs
                                    self.results.technologies.add(tech)
                    
                    logger.info(f"✅ WhatWeb réussi pour {domain}")
                    break  # Sortir de la boucle de retry si succès
                
                except subprocess.TimeoutExpired:
                    logger.warning(f"⚠️ Timeout WhatWeb pour {domain} (tentative {attempt + 1}/{max_retries})")
                    if attempt < max_retries - 1:
                        logger.info(f"🔄 Nouvelle tentative dans {retry_delay} secondes...")
                        time.sleep(retry_delay)
                    else:
                        logger.error(f"❌ Échec WhatWeb après {max_retries} tentatives pour {domain}")
                
                except Exception as e:
                    logger.warning(f"⚠️ Erreur WhatWeb pour {domain}: {e}")
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay)
        
        logger.info(f"✅ WhatWeb: {len(self.results.technologies)} technologies identifiées")
    
    def scan_social_media(self) -> None:
        """Recherche de profils sur les réseaux sociaux"""
        logger.info("🔍 Recherche sur les réseaux sociaux...")
        
        # Extraire le nom de l'organisation du domaine
        org_name = self.root_domain.split('.')[0]
        
        social_platforms = {
            'twitter': f"https://twitter.com/{org_name}",
            'facebook': f"https://facebook.com/{org_name}",
            'linkedin': f"https://linkedin.com/company/{org_name}",
            'instagram': f"https://instagram.com/{org_name}",
            'youtube': f"https://youtube.com/c/{org_name}",
            'github': f"https://github.com/{org_name}"
        }
        
        for platform, url in social_platforms.items():
            try:
                response = self.http_session.get(url)
                if response and response.status_code == 200:
                    # Vérifier si le profil existe vraiment
                    if not any(x in response.text.lower() for x in ['not found', '404', 'does not exist']):
                        self.results.social_media.add(f"{platform}: {url}")
            except Exception as e:
                logger.debug(f"   Réseau social non trouvé pour {platform}: {e}")

        logger.info(f"✅ Réseaux sociaux: {len(self.results.social_media)} profils trouvés")
    
    def scan_all(self) -> OSINTResult:
        """Lance tous les scans OSINT avec corrections"""
        logger.info("🚀 Démarrage du scan OSINT complet...")
        
        # Scans séquentiels pour éviter les erreurs de concurrence
        scan_functions = [
            self.scan_crtsh,
            self.scan_dns_enumeration,
            self.scan_harvester,
            self.scan_whatweb,
            self.scan_social_media
        ]
        
        for scan_func in scan_functions:
            try:
                logger.info(f"🔄 Exécution de {scan_func.__name__}...")
                scan_func()
            except Exception as e:
                logger.error(f"❌ Erreur dans {scan_func.__name__}: {e}")
                continue
        
        # Résolution IP pour tous les sous-domaines - CORRECTION
        logger.info("🔍 Résolution IP des sous-domaines...")
        for subdomain in list(self.results.subdomains):
            try:
                # Utilisation correcte du module socket
                ip = socket.gethostbyname(subdomain)
                if self.validator.validate_ip(ip):
                    self.results.ips.add(ip)
                    logger.debug(f"   {subdomain} -> {ip}")
            except socket.gaierror:
                logger.debug(f"   ❌ Résolution échouée pour {subdomain}")
            except Exception as e:
                logger.debug(f"   ❌ Erreur résolution {subdomain}: {e}")
        
        logger.info(f"✅ OSINT terminé: {len(self.results.subdomains)} sous-domaines, "
                   f"{len(self.results.ips)} IPs, {len(self.results.emails)} emails")
        
        return self.results

class VulnerabilityScanner:
    """Scanner de vulnérabilités"""
    
    def __init__(self, osint_results: OSINTResult):
        self.osint_results = osint_results
        self.vulnerabilities = []
        self.http_session = SecureHTTPSession()
    
    def scan_nmap_vulnerabilities(self) -> None:
        """Scan Nmap avec scripts de vulnérabilités"""
        logger.info("🔍 Scan de vulnérabilités Nmap...")
        
        for ip in list(self.osint_results.ips)[:5]:  # Limiter à 5 IPs
            try:
                # Scan initial rapide des ports
                initial_cmd = [
                    "nmap",
                    "-sS",  # SYN scan plus rapide
                    "-T4",  # Timing agressif
                    "-F",   # Scan des ports les plus communs
                    "-Pn",  # Skip host discovery
                    "--max-retries", "1",  # Réduire les retries
                    "--host-timeout", "30s",  # Timeout par hôte
                    ip
                ]
                
                initial_result = subprocess.run(
                    initial_cmd,
                    capture_output=True,
                    text=True,
                    timeout=45  # Réduire le timeout initial
                )
                
                if initial_result.returncode != 0:
                    continue
                
                # Extraire les ports ouverts
                open_ports = []
                for line in initial_result.stdout.split('\n'):
                    if 'open' in line:
                        port = line.split('/')[0]
                        open_ports.append(port)
                
                if not open_ports:
                    continue
                
                # Scan détaillé uniquement sur les ports ouverts
                ports_str = ','.join(open_ports)
                detailed_cmd = [
                    "nmap",
                    "-sV",  # Version detection
                    "--script", "vuln",  # Uniquement les scripts vuln
                    "--script-timeout", "20s",  # Réduire le timeout des scripts
                    "-T4",
                    "-Pn",
                    "--max-retries", "1",
                    "--host-timeout", "30s",
                    "-p", ports_str,
                    ip
                ]
                
                detailed_result = subprocess.run(
                    detailed_cmd,
                    capture_output=True,
                    text=True,
                    timeout=90  # Réduire le timeout détaillé
                )
                
                if detailed_result.returncode == 0:
                    self.parse_nmap_vulnerabilities(detailed_result.stdout, ip)
                
            except subprocess.TimeoutExpired:
                logger.warning(f"⚠️ Timeout Nmap pour {ip}")
            except Exception as e:
                logger.warning(f"⚠️ Erreur Nmap pour {ip}: {e}")
    
    def parse_nmap_vulnerabilities(self, output: str, ip: str) -> None:
        """Parse les résultats Nmap pour extraire les vulnérabilités"""
        lines = output.split('\n')
        current_vuln = None
        
        for line in lines:
            line = line.strip()
            
            # Détection des CVE
            cve_match = re.search(r'CVE-(\d{4}-\d+)', line)
            if cve_match:
                cve_id = f"CVE-{cve_match.group(1)}"
                
                # Estimer la sévérité basée sur le contexte
                severity = "Medium"
                cvss_score = 5.0
                
                if any(keyword in line.lower() for keyword in ['critical', 'high', 'severe']):
                    severity = "High"
                    cvss_score = 8.0
                elif any(keyword in line.lower() for keyword in ['low', 'info']):
                    severity = "Low"
                    cvss_score = 3.0
                
                vuln = VulnerabilityResult(
                    name=f"Vulnérabilité détectée sur {ip}",
                    severity=severity,
                    description=line,
                    cvss_score=cvss_score,
                    cve_id=cve_id,
                    exploit_available=False
                )
                self.vulnerabilities.append(vuln)
            
            # Détection des services vulnérables
            if 'VULNERABLE' in line.upper():
                vuln = VulnerabilityResult(
                    name=f"Service vulnérable sur {ip}",
                    severity="Medium",
                    description=line,
                    cvss_score=6.0,
                    exploit_available=False
                )
                self.vulnerabilities.append(vuln)
    
    def scan_web_vulnerabilities(self) -> None:
        """Scan des vulnérabilités web communes"""
        logger.info("🔍 Scan des vulnérabilités web...")
        
        domains_to_scan = list(self.osint_results.subdomains)[:10]
        
        for domain in domains_to_scan:
            self.scan_security_headers(domain)
            self.scan_common_files(domain)
            self.scan_ssl_configuration(domain)
    
    def scan_security_headers(self, domain: str) -> None:
        """Vérifie les en-têtes de sécurité"""
        try:
            for protocol in ['https', 'http']:
                url = f"{protocol}://{domain}"
                response = self.http_session.get(url)
                
                if response:
                    headers = response.headers
                    
                    # En-têtes de sécurité requis
                    security_headers = {
                        'Strict-Transport-Security': 'HSTS manquant - Force les connexions HTTPS',
                        'X-Frame-Options': 'X-Frame-Options manquant - Vulnérable au clickjacking',
                        'X-Content-Type-Options': 'X-Content-Type-Options manquant - MIME sniffing possible',
                        'Content-Security-Policy': 'CSP manquant - Vulnérable aux attaques XSS',
                        'X-XSS-Protection': 'X-XSS-Protection manquant ou désactivé'
                    }
                    
                    for header, description in security_headers.items():
                        if header not in headers:
                            vuln = VulnerabilityResult(
                                name=f"En-tête de sécurité manquant: {header}",
                                severity="Medium",
                                description=f"{description} sur {domain}",
                                cvss_score=5.0,
                                mitigation=f"Ajouter l'en-tête {header} dans la configuration du serveur"
                            )
                            self.vulnerabilities.append(vuln)
                    
                    break  # Si HTTPS fonctionne, on s'arrête là
        
        except Exception as e:
            logger.warning(f"⚠️ Erreur scan headers pour {domain}: {e}")
    
    def scan_common_files(self, domain: str) -> None:
        """Vérifie l'accessibilité de fichiers sensibles"""
        sensitive_files = [
            '/.env', '/.git/HEAD', '/wp-config.php', '/config.php',
            '/phpinfo.php', '/server-status', '/server-info',
            '/admin', '/administrator', '/wp-admin',
            '/backup', '/backup.zip', '/database.sql',
            '/.htaccess', '/web.config', '/crossdomain.xml'
        ]
        
        for file_path in sensitive_files:
            try:
                url = f"https://{domain}{file_path}"
                response = self.http_session.get(url)
                
                if response and response.status_code == 200:
                    vuln = VulnerabilityResult(
                        name=f"Fichier sensible accessible: {file_path}",
                        severity="High",
                        description=f"Le fichier {file_path} est accessible publiquement sur {domain}",
                        cvss_score=7.5,
                        mitigation=f"Restreindre l'accès au fichier {file_path}"
                    )
                    self.vulnerabilities.append(vuln)
            
            except Exception as e:
                logger.debug(f"   Fichier sensible non accessible {file_path}: {e}")

    def scan_ssl_configuration(self, domain: str) -> None:
        """Vérifie la configuration SSL"""
        try:
            import ssl
            import socket
            
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Vérifier la validité du certificat
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    if days_until_expiry < 30:
                        vuln = VulnerabilityResult(
                            name="Certificat SSL expirant bientôt",
                            severity="Medium",
                            description=f"Le certificat SSL de {domain} expire dans {days_until_expiry} jours",
                            cvss_score=4.0,
                            mitigation="Renouveler le certificat SSL"
                        )
                        self.vulnerabilities.append(vuln)
        
        except Exception as e:
            logger.warning(f"⚠️ Erreur vérification SSL pour {domain}: {e}")
    
    def scan_all(self) -> List[VulnerabilityResult]:
        """Lance tous les scans de vulnérabilités"""
        logger.info("🚀 Démarrage du scan de vulnérabilités...")
        
        scan_functions = [
            self.scan_nmap_vulnerabilities,
            self.scan_web_vulnerabilities
        ]
        
        for scan_func in scan_functions:
            try:
                scan_func()
            except Exception as e:
                logger.error(f"❌ Erreur dans {scan_func.__name__}: {e}")
        
        logger.info(f"✅ Scan de vulnérabilités terminé: {len(self.vulnerabilities)} vulnérabilités trouvées")
        
        return self.vulnerabilities

class ExploitSuggester:
    """Générateur de suggestions d'exploitation corrigé"""
    
    def __init__(self, vulnerabilities: List):
        self.vulnerabilities = vulnerabilities
        self.exploit_suggestions = []
    
    def generate_exploit_suggestions(self) -> List[Dict[str, Any]]:
        """Génère des suggestions d'exploitation avec corrections"""
        logger.info("🎯 Génération des suggestions d'exploitation...")
        
        if not self.vulnerabilities:
            logger.info("ℹ️ Aucune vulnérabilité détectée, aucune suggestion générée")
            return []
        
        # Base de données des exploits corrigée
        exploit_db = {
            'apache': {
                'tools': ['nikto', 'dirb', 'gobuster'],
                'techniques': ['Directory traversal', 'CGI exploitation', 'Module vulnerabilities'],
                'commands': [
                    'nikto -h TARGET',
                    'dirb http://TARGET /usr/share/wordlists/dirb/common.txt',
                    'gobuster dir -u http://TARGET -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
                ]
            },
            'nginx': {
                'tools': ['nmap', 'curl'],
                'techniques': ['Configuration issues', 'Version-specific exploits'],
                'commands': [
                    'nmap -p 80,443 --script http-methods TARGET',
                    'curl -I TARGET',
                    'nmap --script http-config-backup TARGET'
                ]
            },
            'wordpress': {
                'tools': ['wpscan', 'wp-vulnerability-scanner'],
                'techniques': ['Plugin vulnerabilities', 'Theme exploits', 'User enumeration'],
                'commands': [
                    'wpscan --url http://TARGET --enumerate u,p,t',
                    'curl TARGET/wp-json/wp/v2/users',
                    'wpscan --url http://TARGET --passwords /usr/share/wordlists/rockyou.txt'
                ]
            },
            'ssh': {
                'tools': ['hydra', 'nmap', 'ssh-audit'],
                'techniques': ['Brute force attack', 'Key-based attacks', 'Configuration analysis'],
                'commands': [
                    'nmap -p 22 --script ssh-auth-methods TARGET',
                    'hydra -L users.txt -P passwords.txt ssh://TARGET',
                    'ssh-audit TARGET'
                ]
            },
            'ssl': {
                'tools': ['testssl.sh', 'sslscan', 'nmap'],
                'techniques': ['Weak ciphers', 'Certificate issues', 'Protocol vulnerabilities'],
                'commands': [
                    'testssl.sh TARGET',
                    'sslscan TARGET',
                    'nmap --script ssl-enum-ciphers -p 443 TARGET'
                ]
            },
            'generic': {
                'tools': ['nmap', 'whatweb', 'curl'],
                'techniques': ['Port scanning', 'Service enumeration', 'Banner grabbing'],
                'commands': [
                    'nmap -sV -sC TARGET',
                    'nmap --script vuln TARGET',
                    'whatweb TARGET'
                ]
            }
        }
        
        for vuln in self.vulnerabilities:
            try:
                suggestions = self.create_exploit_suggestion(vuln, exploit_db)
                if suggestions:
                    self.exploit_suggestions.extend(suggestions)
            except Exception as e:
                logger.error(f"❌ Erreur génération suggestion pour {getattr(vuln, 'name', 'vulnérabilité inconnue')}: {e}")
        
        logger.info(f"✅ {len(self.exploit_suggestions)} suggestions d'exploitation générées")
        return self.exploit_suggestions
    
    def create_exploit_suggestion(self, vuln, exploit_db: Dict) -> List[Dict[str, Any]]:
        """Crée une suggestion d'exploitation pour une vulnérabilité avec corrections"""
        suggestions = []
        
        try:
            # Obtenir les attributs de vulnérabilité de manière sécurisée
            vuln_name = getattr(vuln, 'name', 'Vulnérabilité inconnue')
            vuln_severity = getattr(vuln, 'severity', 'Medium')
            vuln_description = getattr(vuln, 'description', '').lower()
            
            # Identifier le type de service/technologie
            service_found = None
            for service, exploit_info in exploit_db.items():
                if service != 'generic' and service in vuln_description:
                    service_found = service
                    break
            
            # Si aucun service spécifique trouvé, utiliser générique
            if not service_found:
                service_found = 'generic'
            
            exploit_info = exploit_db[service_found]
            
            suggestion = {
                'vulnerability': vuln_name,
                'severity': vuln_severity,
                'service': service_found,
                'tools': exploit_info['tools'],
                'techniques': exploit_info['techniques'],
                'commands': exploit_info['commands'],
                'precautions': self.generate_precautions(vuln_severity),
                'legal_notice': "⚠️ N'utilisez ces techniques que sur vos propres systèmes ou avec autorisation explicite."
            }
            suggestions.append(suggestion)
            
        except Exception as e:
            logger.error(f"❌ Erreur création suggestion: {e}")
        
        return suggestions
    
    def generate_precautions(self, severity: str) -> List[str]:
        """Génère des précautions basées sur la sévérité"""
        precautions = [
            "Vérifiez que vous avez l'autorisation d'effectuer ces tests",
            "Documentez toutes vos actions",
            "Utilisez un environnement de test si possible"
        ]
        
        if severity in ['High', 'Critical']:
            precautions.extend([
                "Cette vulnérabilité est critique - procédez avec précaution",
                "Informez immédiatement l'équipe de sécurité",
                "Évitez les tests qui pourraient causer une interruption de service"
            ])
        
        return precautions

class MetasploitScanner:
    """Scanner de vulnérabilités utilisant Metasploit"""
    
    def __init__(self, domain: str, scan_depth: str = "quick"):
        self.domain = domain
        self.results = []
        self.logger = logging.getLogger(__name__)
        self.scan_depth = scan_depth  # "quick", "normal", "deep"
        self.timeout = 300  # 5 minutes par défaut
    
    def scan_with_metasploit(self) -> List[Dict[str, Any]]:
        """Effectue un scan avec Metasploit"""
        logger.info("🔍 Lancement du scan Metasploit...")
        
        try:
            # Vérifier si msfconsole est disponible
            if not self._check_metasploit():
                logger.error("❌ Metasploit n'est pas installé ou n'est pas dans le PATH")
                return []
            
            # Préparer le script Metasploit
            script_content = self._generate_metasploit_script()
            script_path = "temp/metasploit_scan.rc"
            
            # Créer le répertoire temp s'il n'existe pas
            os.makedirs("temp", exist_ok=True)
            
            # Écrire le script
            with open(script_path, 'w') as f:
                f.write(script_content)
            
            # Exécuter le scan avec timeout
            cmd = ['msfconsole', '-q', '-r', script_path]
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            except subprocess.TimeoutExpired:
                logger.warning("⚠️ Le scan Metasploit a dépassé le délai maximum")
                return self.results
            
            if result.returncode != 0:
                logger.error(f"❌ Erreur lors du scan Metasploit: {result.stderr}")
                return []
            
            # Analyser les résultats
            self._parse_metasploit_output(result.stdout)
            
            logger.info(f"✅ Scan Metasploit terminé: {len(self.results)} vulnérabilités trouvées")
            return self.results
            
        except Exception as e:
            logger.error(f"❌ Erreur lors du scan Metasploit: {e}")
            return []
    
    def _check_metasploit(self) -> bool:
        """Vérifie si Metasploit est installé"""
        try:
            result = subprocess.run(['which', 'msfconsole'], capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False
    
    def _generate_metasploit_script(self) -> str:
        """Génère le script Metasploit pour le scan"""
        # Modules de base pour tous les niveaux de scan
        base_modules = f"""
# Configuration
setg RHOSTS {self.domain}
setg VERBOSE true
setg TIMEOUT 30

# Scan des ports ouverts (rapide)
use auxiliary/scanner/portscan/tcp
set PORTS 21,22,23,25,80,443,445,3306,3389,8080
run

# Scan des vulnérabilités web de base
use auxiliary/scanner/http/http_version
run
"""
        
        # Modules supplémentaires selon la profondeur
        if self.scan_depth == "quick":
            return base_modules + "\nexit"
            
        elif self.scan_depth == "normal":
            return base_modules + """
# Scan des vulnérabilités web avancées
use auxiliary/scanner/http/dir_scanner
set THREADS 10
run

use auxiliary/scanner/http/http_put
run

# Scan des vulnérabilités SSL/TLS
use auxiliary/scanner/ssl/openssl_heartbleed
run

# Scan des vulnérabilités SSH
use auxiliary/scanner/ssh/ssh_version
run

exit
"""
        else:  # deep
            return base_modules + """
# Scan des vulnérabilités web avancées
use auxiliary/scanner/http/dir_scanner
set THREADS 20
run

use auxiliary/scanner/http/http_put
run

use auxiliary/scanner/http/http_traversal
run

# Scan des vulnérabilités SSL/TLS
use auxiliary/scanner/ssl/openssl_heartbleed
run

use auxiliary/scanner/ssl/ssl_version
run

# Scan des vulnérabilités SMB
use auxiliary/scanner/smb/smb_version
run

use auxiliary/scanner/smb/smb_enumshares
run

# Scan des vulnérabilités SSH
use auxiliary/scanner/ssh/ssh_version
run

use auxiliary/scanner/ssh/ssh_enumusers
run

# Scan des vulnérabilités FTP
use auxiliary/scanner/ftp/ftp_version
run

use auxiliary/scanner/ftp/ftp_anonymous
run

# Scan des vulnérabilités DNS
use auxiliary/scanner/dns/dns_amp
run

exit
"""
    
    def _parse_metasploit_output(self, output: str) -> None:
        """Analyse la sortie de Metasploit pour extraire les vulnérabilités"""
        lines = output.split('\n')
        current_vuln = None
        
        for line in lines:
            line = line.strip()
            
            # Détection des vulnérabilités
            if '[+]' in line:
                vuln_info = {
                    'name': line.split('[+]')[1].strip(),
                    'severity': 'Medium',
                    'description': line,
                    'source': 'Metasploit',
                    'details': []
                }
                
                # Déterminer la sévérité
                if any(keyword in line.lower() for keyword in ['critical', 'high', 'severe']):
                    vuln_info['severity'] = 'High'
                elif any(keyword in line.lower() for keyword in ['low', 'info']):
                    vuln_info['severity'] = 'Low'
                
                self.results.append(vuln_info)
                current_vuln = vuln_info
            
            # Ajouter des détails à la vulnérabilité courante
            elif current_vuln and line and not line.startswith('[*]'):
                current_vuln['details'].append(line)

class RealDataReportGenerator:
    """Générateur de rapports basé sur les données réelles"""
    
    def __init__(self, domain: str, osint_results, vulnerabilities: List, exploit_suggestions: List[Dict[str, Any]]):
        self.domain = domain
        self.osint_results = osint_results
        self.vulnerabilities = vulnerabilities
        self.exploit_suggestions = exploit_suggestions
        self.real_data = self._prepare_real_data()
    
    def _prepare_real_data(self) -> Dict[str, Any]:
        """Prépare les données réelles pour la génération des rapports"""
        return {
            'collected_assets': {
                'subdomains': list(getattr(self.osint_results, 'subdomains', set())),
                'ips': list(getattr(self.osint_results, 'ips', set())),
                'emails': list(getattr(self.osint_results, 'emails', set())),
                'technologies': list(getattr(self.osint_results, 'technologies', set()))
            },
            'target_analysis': {
                'total_targets': len(getattr(self.osint_results, 'subdomains', set())) + 1,
                'scanned_ips': list(getattr(self.osint_results, 'ips', set())),
                'scanned_domains': list(getattr(self.osint_results, 'subdomains', set())) + [self.domain]
            },
            'security_issues': self._categorize_security_issues()
        }
    
    def _categorize_security_issues(self) -> Dict[str, List[Dict[str, Any]]]:
        """Catégorise les problèmes de sécurité par type"""
        categories = defaultdict(list)
        
        for vuln in self.vulnerabilities:
            category = self._determine_category(vuln)
            categories[category].append({
                'name': getattr(vuln, 'name', 'Inconnu'),
                'severity': getattr(vuln, 'severity', 'Medium'),
                'description': getattr(vuln, 'description', ''),
                'target': getattr(vuln, 'target', self.domain)
            })
        
        return dict(categories)
    
    def _determine_category(self, vuln) -> str:
        """Détermine la catégorie d'une vulnérabilité"""
        name = getattr(vuln, 'name', '').lower()
        
        if 'cve' in name or 'exploit' in name:
            return 'CVE & Exploits'
        elif 'ssl' in name or 'tls' in name:
            return 'SSL/TLS Configuration'
        elif 'header' in name:
            return 'HTTP Security Headers'
        elif 'port' in name:
            return 'Open Ports'
        elif 'version' in name:
            return 'Outdated Software'
        else:
            return 'Other Security Issues'
    
    def generate_real_data_markdown_report(self) -> str:
        """Génère un rapport Markdown basé sur les données réelles"""
        report = []
        
        # En-tête
        report.append("# 🕷️ SpiderIntel - Rapport d'Analyse Complet")
        report.append(f"**Domaine cible:** {self.domain}")
        report.append(f"**Date d'analyse:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"**Version:** SpiderIntel v2.0.0")
        report.append("\n" + "="*80 + "\n")
        
        # Résumé exécutif avec données réelles
        report.append("## 📊 Résumé Exécutif")
        assets = self.real_data['collected_assets']
        targets = self.real_data['target_analysis']
        issues = self.real_data['security_issues']
        
        report.append(f"- **Cibles analysées:** {targets['total_targets']}")
        report.append(f"- **Assets découverts:** {len(assets['subdomains']) + len(assets['ips']) + len(assets['emails'])}")
        report.append(f"- **Problèmes de sécurité:** {len(self.vulnerabilities)}")
        report.append(f"- **Catégories de risques:** {len(issues)}")
        
        # Détails des découvertes
        report.append("\n## 🔍 Découvertes Détaillées")
        
        # Sous-domaines
        if assets['subdomains']:
            report.append("\n### Sous-domaines")
            for subdomain in sorted(assets['subdomains']):
                report.append(f"- {subdomain}")
        
        # IPs
        if assets['ips']:
            report.append("\n### Adresses IP")
            for ip in sorted(assets['ips']):
                report.append(f"- {ip}")
        
        # Emails
        if assets['emails']:
            report.append("\n### Emails")
            for email in sorted(assets['emails']):
                report.append(f"- {email}")
        
        # Technologies
        if hasattr(self.osint_results, 'technologies') and self.osint_results.technologies:
            report.append("\n### Technologies Détectées")
            for tech in sorted(self.osint_results.technologies):
                report.append(f"- {tech}")
        
        # Ports et Services
        if hasattr(self.osint_results, 'ports') and self.osint_results.ports:
            report.append("\n### Ports et Services")
            for ip, ports in self.osint_results.ports.items():
                report.append(f"\n#### {ip}")
                for port in sorted(ports):
                    report.append(f"- Port {port}")
        
        # Certificats SSL
        if hasattr(self.osint_results, 'certificates') and self.osint_results.certificates:
            report.append("\n### Certificats SSL")
            for domain, cert in self.osint_results.certificates.items():
                report.append(f"\n#### {domain}")
                report.append(f"- **Émetteur:** {cert.get('issuer', 'Inconnu')}")
                report.append(f"- **Valide jusqu'au:** {cert.get('valid_until', 'Inconnu')}")
                report.append(f"- **Algorithme:** {cert.get('algorithm', 'Inconnu')}")
        
        # Vulnérabilités
        if self.vulnerabilities:
            report.append("\n## ⚠️ Vulnérabilités")
            for vuln in self.vulnerabilities:
                report.append(f"\n### {vuln.name}")
                report.append(f"- **Sévérité:** {vuln.severity}")
                report.append(f"- **Description:** {vuln.description}")
                report.append(f"- **Score CVSS:** {vuln.cvss_score}")
                if hasattr(vuln, 'cve_id') and vuln.cve_id:
                    report.append(f"- **CVE:** {vuln.cve_id}")
                if hasattr(vuln, 'mitigation') and vuln.mitigation:
                    report.append(f"- **Mitigation:** {vuln.mitigation}")
                if hasattr(vuln, 'references') and vuln.references:
                    report.append("- **Références:**")
                    for ref in vuln.references:
                        report.append(f"  - {ref}")
        
        # Suggestions d'exploitation
        if self.exploit_suggestions:
            report.append("\n## 💡 Suggestions d'Exploitation")
            for exploit in self.exploit_suggestions:
                report.append(f"\n### {exploit.get('vulnerability', 'Vulnérabilité inconnue')}")
                if 'service' in exploit:
                    report.append(f"- **Service:** {exploit['service']}")
                if 'tools' in exploit:
                    report.append(f"- **Outils recommandés:** {', '.join(exploit['tools'])}")
                if 'commands' in exploit:
                    report.append("- **Commandes:**")
                    report.append("```bash")
                    for cmd in exploit['commands']:
                        report.append(cmd)
                    report.append("```")
                if 'legal_notice' in exploit:
                    report.append(f"- **⚠️ Avertissement:** {exploit['legal_notice']}")
        
        # Recommandations de sécurité
        report.append("\n## 🛡️ Recommandations de Sécurité")
        report.append("\n### Actions Prioritaires")
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            vulns = [v for v in self.vulnerabilities if v.severity == severity]
            if vulns:
                report.append(f"\n#### Vulnérabilités {severity}")
                for vuln in vulns:
                    report.append(f"- {vuln.name}: {vuln.mitigation}")
        
        return "\n".join(report)
    
    def generate_real_data_json_report(self) -> str:
        """Génère un rapport JSON basé sur les données réelles"""
        return json.dumps(self.real_data, indent=2, ensure_ascii=False)

class ReportGenerator:
    """Générateur de rapports corrigé"""
    
    def __init__(self, domain: str, osint_results, vulnerabilities: List, exploit_suggestions: List[Dict[str, Any]]):
        self.domain = domain
        self.osint_results = osint_results
        self.vulnerabilities = vulnerabilities
        self.exploit_suggestions = exploit_suggestions
    
    def generate_comprehensive_report(self) -> str:
        """Génère un rapport complet avec uniquement les données réelles"""
        report = []
        
        # En-tête
        report.append("# 🕷️ SpiderIntel - Rapport d'Analyse Complet")
        report.append(f"**Domaine cible:** {self.domain}")
        report.append(f"**Date d'analyse:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"**Version:** SpiderIntel v2.0.0")
        report.append("\n" + "="*80 + "\n")
        
        # Résumé exécutif avec données réelles uniquement
        report.append("## 📊 Résumé Exécutif")
        if hasattr(self.osint_results, 'subdomains') and self.osint_results.subdomains:
            report.append(f"- **Sous-domaines découverts:** {len(self.osint_results.subdomains)}")
        if hasattr(self.osint_results, 'ips') and self.osint_results.ips:
            report.append(f"- **Adresses IP identifiées:** {len(self.osint_results.ips)}")
        if hasattr(self.osint_results, 'emails') and self.osint_results.emails:
            report.append(f"- **Emails trouvés:** {len(self.osint_results.emails)}")
        if hasattr(self.osint_results, 'technologies') and self.osint_results.technologies:
            report.append(f"- **Technologies détectées:** {len(self.osint_results.technologies)}")
        if self.vulnerabilities:
            report.append(f"- **Vulnérabilités identifiées:** {len(self.vulnerabilities)}")
        if self.exploit_suggestions:
            report.append(f"- **Suggestions d'exploitation:** {len(self.exploit_suggestions)}")
        
        # Découvertes OSINT (uniquement si des données existent)
        osint_sections_added = False
        if hasattr(self.osint_results, 'subdomains') and self.osint_results.subdomains:
            if not osint_sections_added:
                report.append("\n## 🔍 Découvertes OSINT")
                osint_sections_added = True
            report.append("\n### Sous-domaines")
            for subdomain in sorted(self.osint_results.subdomains):
                report.append(f"- {subdomain}")
        
        if hasattr(self.osint_results, 'ips') and self.osint_results.ips:
            if not osint_sections_added:
                report.append("\n## 🔍 Découvertes OSINT")
                osint_sections_added = True
            report.append("\n### Adresses IP")
            for ip in sorted(self.osint_results.ips):
                report.append(f"- {ip}")
        
        if hasattr(self.osint_results, 'emails') and self.osint_results.emails:
            if not osint_sections_added:
                report.append("\n## 🔍 Découvertes OSINT")
                osint_sections_added = True
            report.append("\n### Emails")
            for email in sorted(self.osint_results.emails):
                report.append(f"- {email}")
        
        if hasattr(self.osint_results, 'technologies') and self.osint_results.technologies:
            if not osint_sections_added:
                report.append("\n## 🔍 Découvertes OSINT")
                osint_sections_added = True
            report.append("\n### Technologies")
            for tech in sorted(self.osint_results.technologies):
                report.append(f"- {tech}")
        
        # Vulnérabilités (uniquement si des vulnérabilités existent)
        if self.vulnerabilities:
            report.append("\n## ⚠️ Vulnérabilités")
            for vuln in self.vulnerabilities:
                report.append(f"\n### {vuln.name}")
                report.append(f"- **Sévérité:** {vuln.severity}")
                report.append(f"- **Description:** {vuln.description}")
                report.append(f"- **Score CVSS:** {vuln.cvss_score}")
                if hasattr(vuln, 'mitigation') and vuln.mitigation:
                    report.append(f"- **Mitigation:** {vuln.mitigation}")
        
        # Suggestions d'exploitation (uniquement si des suggestions existent)
        if self.exploit_suggestions:
            report.append("\n## 💡 Suggestions d'Exploitation")
            for exploit in self.exploit_suggestions:
                report.append(f"\n### {exploit.get('vulnerability', 'Vulnérabilité inconnue')}")
                if 'service' in exploit:
                    report.append(f"- **Service:** {exploit['service']}")
                if 'tools' in exploit:
                    report.append(f"- **Outils recommandés:** {', '.join(exploit['tools'])}")
                if 'commands' in exploit:
                    report.append(f"- **Commandes:**")
                    report.append("```bash")
                    for cmd in exploit['commands']:
                        report.append(cmd)
                    report.append("```")
                if 'legal_notice' in exploit:
                    report.append(f"- **⚠️ Avertissement:** {exploit['legal_notice']}")
        
        return "\n".join(report)
    
    def generate_html_report(self) -> str:
        """Génère un rapport HTML complet avec uniquement les données réelles"""
        # Préparation des données pour les graphiques (uniquement les données réelles)
        summary_data = []
        summary_labels = []
        
        if hasattr(self.osint_results, 'subdomains') and self.osint_results.subdomains:
            summary_data.append(len(self.osint_results.subdomains))
            summary_labels.append('Sous-domaines')
        
        if hasattr(self.osint_results, 'ips') and self.osint_results.ips:
            summary_data.append(len(self.osint_results.ips))
            summary_labels.append('IPs')
        
        if hasattr(self.osint_results, 'emails') and self.osint_results.emails:
            summary_data.append(len(self.osint_results.emails))
            summary_labels.append('Emails')
        
        if hasattr(self.osint_results, 'technologies') and self.osint_results.technologies:
            summary_data.append(len(self.osint_results.technologies))
            summary_labels.append('Technologies')
        
        if self.vulnerabilities:
            summary_data.append(len(self.vulnerabilities))
            summary_labels.append('Vulnérabilités')
        
        # Distribution des vulnérabilités (uniquement si des vulnérabilités existent)
        vulnerability_data = []
        vulnerability_labels = []
        if self.vulnerabilities:
            vuln_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
            for vuln in self.vulnerabilities:
                severity = getattr(vuln, 'severity', 'Medium')
                vuln_counts[severity] = vuln_counts.get(severity, 0) + 1
            
            for severity in ['Critical', 'High', 'Medium', 'Low']:
                if vuln_counts[severity] > 0:
                    vulnerability_data.append(vuln_counts[severity])
                    vulnerability_labels.append(severity)
        
        # Données OSINT (uniquement si des données existent)
        osint_data = []
        osint_labels = []
        if hasattr(self.osint_results, 'subdomains') and self.osint_results.subdomains:
            osint_data.append(len(self.osint_results.subdomains))
            osint_labels.append('Sous-domaines')
        if hasattr(self.osint_results, 'ips') and self.osint_results.ips:
            osint_data.append(len(self.osint_results.ips))
            osint_labels.append('IPs')
        if hasattr(self.osint_results, 'emails') and self.osint_results.emails:
            osint_data.append(len(self.osint_results.emails))
            osint_labels.append('Emails')
        
        # Technologies (uniquement si des technologies existent)
        tech_labels = []
        tech_data = []
        if hasattr(self.osint_results, 'technologies') and self.osint_results.technologies:
            tech_labels = list(self.osint_results.technologies)[:10]  # Limiter à 10 pour la lisibilité
            tech_data = [1] * len(tech_labels)
        
        # Table des vulnérabilités (uniquement si des vulnérabilités existent)
        vulnerabilities_rows = []
        if self.vulnerabilities:
            for vuln in self.vulnerabilities:
                severity_class = getattr(vuln, 'severity', 'medium').lower()
                row = f"""
                <tr class="vulnerability-{severity_class}">
                    <td>{getattr(vuln, 'name', 'Nom inconnu')}</td>
                    <td>{getattr(vuln, 'severity', 'Medium')}</td>
                    <td>{getattr(vuln, 'description', 'Description non disponible')}</td>
                    <td>{getattr(vuln, 'cvss_score', 0.0)}</td>
                    <td>{getattr(vuln, 'mitigation', 'Aucune mitigation spécifiée')}</td>
                </tr>
                """
                vulnerabilities_rows.append(row)
        
        # Table des exploits (uniquement si des suggestions existent)
        exploits_rows = []
        if self.exploit_suggestions:
            for exploit in self.exploit_suggestions:
                commands_str = ""
                if 'commands' in exploit and exploit['commands']:
                    commands_str = "\n".join(exploit['commands'])
                
                row = f"""
                <tr>
                    <td>{exploit.get('vulnerability', 'Inconnu')}</td>
                    <td>{exploit.get('service', 'Générique')}</td>
                    <td><pre style="font-size: 12px; max-width: 300px; overflow-x: auto;">{commands_str}</pre></td>
                    <td>{exploit.get('severity', 'Medium')}</td>
                </tr>
                """
                exploits_rows.append(row)
        
        # Template HTML corrigé
        html_template = f"""
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>SpiderIntel - Rapport d'Analyse - {self.domain}</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }}
                .card {{ margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .chart-container {{ position: relative; height: 400px; margin: 20px 0; }}
                .vulnerability-critical {{ background-color: #ffebee; }}
                .vulnerability-high {{ background-color: #ffebee; }}
                .vulnerability-medium {{ background-color: #fff3e0; }}
                .vulnerability-low {{ background-color: #e8f5e9; }}
                pre {{ background-color: #f8f9fa; padding: 10px; border-radius: 4px; margin: 0; }}
                .table td, .table th {{ vertical-align: middle; }}
                .no-data {{ text-align: center; color: #6c757d; font-style: italic; }}
            </style>
        </head>
        <body>
            <div class="container-fluid py-4">
                <h1 class="text-center mb-4">🕷️ SpiderIntel - Rapport d'Analyse</h1>
                <div class="alert alert-info">
                    <strong>Domaine analysé:</strong> {self.domain}<br>
                    <strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </div>
                
                {"" if not summary_data else f'''
                <div class="row">
                    <div class="col-md-12">
                        <div class="card">
                            <div class="card-body">
                                <h2>📊 Résumé Exécutif</h2>
                                <div class="row">
                                    <div class="col-md-6">
                                        <div class="chart-container">
                                            <canvas id="summaryChart"></canvas>
                                        </div>
                                    </div>
                                    <div class="col-md-6">
                                        <div class="chart-container">
                                            <canvas id="vulnerabilityChart"></canvas>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                '''}
                
                {"" if not osint_data else f'''
                <div class="row">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-body">
                                <h2>🔍 Découvertes OSINT</h2>
                                <div class="chart-container">
                                    <canvas id="osintChart"></canvas>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-body">
                                <h2>🔧 Technologies Détectées</h2>
                                <div class="chart-container">
                                    <canvas id="techChart"></canvas>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                '''}
                
                {"<div class='alert alert-warning no-data'>Aucune vulnérabilité détectée</div>" if not vulnerabilities_rows else f'''
                <div class="row">
                    <div class="col-md-12">
                        <div class="card">
                            <div class="card-body">
                                <h2>⚠️ Vulnérabilités</h2>
                                <div class="table-responsive">
                                    <table class="table table-striped">
                                        <thead>
                                            <tr>
                                                <th>Nom</th>
                                                <th>Sévérité</th>
                                                <th>Description</th>
                                                <th>Score CVSS</th>
                                                <th>Mitigation</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {''.join(vulnerabilities_rows)}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                '''}
                
                {"<div class='alert alert-info no-data'>Aucune suggestion d'exploitation générée</div>" if not exploits_rows else f'''
                <div class="row">
                    <div class="col-md-12">
                        <div class="card">
                            <div class="card-body">
                                <h2>💡 Suggestions d'Exploitation</h2>
                                <div class="alert alert-warning">
                                    <strong>⚠️ Avertissement:</strong> Ces techniques ne doivent être utilisées que sur vos propres systèmes ou avec autorisation explicite.
                                </div>
                                <div class="table-responsive">
                                    <table class="table table-striped">
                                        <thead>
                                            <tr>
                                                <th>Vulnérabilité</th>
                                                <th>Service</th>
                                                <th>Commandes</th>
                                                <th>Niveau</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {''.join(exploits_rows)}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                '''}
            </div>
            
            <script>
                // Vérifier si nous avons des données avant de créer les graphiques
                {"" if not summary_data else f'''
                // Graphique de résumé
                new Chart(document.getElementById('summaryChart'), {{
                    type: 'bar',
                    data: {{
                        labels: {summary_labels},
                        datasets: [{{
                            label: 'Découvertes',
                            data: {summary_data},
                            backgroundColor: [
                                'rgba(54, 162, 235, 0.8)',
                                'rgba(255, 99, 132, 0.8)',
                                'rgba(75, 192, 192, 0.8)',
                                'rgba(255, 206, 86, 0.8)',
                                'rgba(153, 102, 255, 0.8)'
                            ]
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {{
                            title: {{
                                display: true,
                                text: 'Résumé des Découvertes'
                            }}
                        }}
                    }}
                }});
                '''}
                
                {"" if not vulnerability_data else f'''
                // Graphique des vulnérabilités
                new Chart(document.getElementById('vulnerabilityChart'), {{
                    type: 'pie',
                    data: {{
                        labels: {vulnerability_labels},
                        datasets: [{{
                            data: {vulnerability_data},
                            backgroundColor: [
                                'rgba(255, 0, 0, 0.8)',
                                'rgba(255, 165, 0, 0.8)',
                                'rgba(255, 255, 0, 0.8)',
                                'rgba(0, 255, 0, 0.8)'
                            ]
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {{
                            title: {{
                                display: true,
                                text: 'Distribution des Vulnérabilités'
                            }}
                        }}
                    }}
                }});
                '''}
                
                {"" if not osint_data else f'''
                // Graphique OSINT
                new Chart(document.getElementById('osintChart'), {{
                    type: 'doughnut',
                    data: {{
                        labels: {osint_labels},
                        datasets: [{{
                            data: {osint_data},
                            backgroundColor: [
                                'rgba(54, 162, 235, 0.8)',
                                'rgba(255, 99, 132, 0.8)',
                                'rgba(75, 192, 192, 0.8)'
                            ]
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {{
                            title: {{
                                display: true,
                                text: 'Découvertes OSINT'
                            }}
                        }}
                    }}
                }});
                '''}
                
                {"" if not tech_data else f'''
                // Graphique des technologies
                new Chart(document.getElementById('techChart'), {{
                    type: 'bar',
                    data: {{
                        labels: {tech_labels},
                        datasets: [{{
                            label: 'Technologies',
                            data: {tech_data},
                            backgroundColor: 'rgba(75, 192, 192, 0.8)'
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        indexAxis: 'y',
                        plugins: {{
                            title: {{
                                display: true,
                                text: 'Technologies Détectées'
                            }}
                        }}
                    }}
                }});
                '''}
            </script>
        </body>
        </html>
        """
        
        return html_template

class SpiderIntelMain:
    """Classe principale corrigée"""
    
    def __init__(self, domain: str, output_dir: str = "reports", scan_depth: str = "quick"):
        self.domain = domain
        self.output_dir = Path(output_dir)
        self.logger = logging.getLogger(__name__)
        self.scan_depth = scan_depth
    
    def run_complete_analysis(self) -> Dict[str, Any]:
        """Exécute une analyse complète avec rapports basés sur les données réelles"""
        logger.info(f"🚀 Démarrage de l'analyse complète pour {self.domain}")
        start_time = time.time()
        
        try:
            # Création du répertoire de sortie
            domain_output_dir = self.output_dir / self.domain
            domain_output_dir.mkdir(parents=True, exist_ok=True)
            
            # Phase 1: Scan OSINT
            logger.info("🔍 Phase 1: Scan OSINT")
            osint_scanner = OSINTScanner(self.domain)
            osint_results = osint_scanner.scan_all()
            
            # Phase 2: Scan des vulnérabilités
            logger.info("🔍 Phase 2: Scan des vulnérabilités")
            vuln_scanner = VulnerabilityScanner(osint_results)
            vulnerabilities = vuln_scanner.scan_all()
            
            # Phase 3: Scan Metasploit
            logger.info("🔍 Phase 3: Scan Metasploit")
            metasploit_scanner = MetasploitScanner(self.domain, self.scan_depth)
            metasploit_results = metasploit_scanner.scan_with_metasploit()
            
            # Fusionner les résultats des vulnérabilités
            vulnerabilities.extend([
                VulnerabilityResult(
                    name=v['name'],
                    severity=v['severity'],
                    description=v['description'],
                    cvss_score=8.0 if v['severity'] == 'High' else 5.0,
                    exploit_available=True,
                    mitigation="Vérifier la configuration et appliquer les correctifs de sécurité"
                ) for v in metasploit_results
            ])
            
            # Phase 4: Suggestions d'exploitation
            logger.info("🎯 Phase 4: Génération des suggestions d'exploitation")
            exploit_suggester = ExploitSuggester(vulnerabilities)
            exploit_suggestions = exploit_suggester.generate_exploit_suggestions()
            
            # Phase 5: Génération des rapports
            logger.info("📝 Phase 5: Génération des rapports")
            report_generator = RealDataReportGenerator(
                self.domain, osint_results, vulnerabilities, exploit_suggestions
            )
            
            timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            generated_reports = {}
            
            # Génération rapport Markdown
            try:
                logger.info("📝 Génération du rapport Markdown...")
                md_report = report_generator.generate_real_data_markdown_report()
                md_path = domain_output_dir / f"spiderintel_analysis_{timestamp}.md"
                
                with open(md_path, 'w', encoding='utf-8') as f:
                    f.write(md_report)
                generated_reports['markdown'] = md_path
                logger.info(f"✅ Rapport Markdown créé: {md_path}")
                
            except Exception as e:
                logger.error(f"❌ Erreur génération rapport Markdown: {e}")
            
            # Génération rapport JSON
            try:
                logger.info("📊 Génération du rapport JSON...")
                json_report = report_generator.generate_real_data_json_report()
                json_path = domain_output_dir / f"spiderintel_analysis_{timestamp}.json"
                
                with open(json_path, 'w', encoding='utf-8') as f:
                    f.write(json_report)
                generated_reports['json'] = json_path
                logger.info(f"✅ Rapport JSON créé: {json_path}")
                
            except Exception as e:
                logger.error(f"❌ Erreur génération rapport JSON: {e}")
            
            # Génération du résumé exécutif
            try:
                logger.info("📋 Génération du résumé exécutif...")
                summary = self.generate_executive_summary(report_generator)
                summary_path = domain_output_dir / f"spiderintel_summary_{timestamp}.md"
                
                with open(summary_path, 'w', encoding='utf-8') as f:
                    f.write(summary)
                generated_reports['summary'] = summary_path
                logger.info(f"✅ Résumé exécutif créé: {summary_path}")
                
            except Exception as e:
                logger.error(f"❌ Erreur génération résumé exécutif: {e}")
            
            # Calcul du temps d'exécution
            execution_time = time.time() - start_time
            logger.info(f"⏱️ Temps d'exécution total: {execution_time:.2f} secondes")
            
            return {
                'osint_results': osint_results,
                'vulnerabilities': vulnerabilities,
                'exploit_suggestions': exploit_suggestions,
                'reports': generated_reports,
                'execution_time': execution_time
            }
            
        except Exception as e:
            logger.error(f"❌ Erreur lors de l'analyse complète: {e}")
            raise
    
    def generate_enhanced_html_report(self, report_generator) -> str:
        """Génère un rapport HTML basé sur les données réelles avec interface moderne"""
        real_data = report_generator.real_data
        
        # Préparer les données pour l'interface
        assets = real_data['collected_assets']
        targets = real_data['target_analysis'] 
        issues = real_data['security_issues']
        
        # Compter les problèmes par sévérité
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for problems in issues.values():
            for problem in problems:
                severity_counts[problem['severity']] += 1
        
        html_template = f"""
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>SpiderIntel - Analyse de Sécurité - {self.domain}</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }}
                .main-container {{ background: white; border-radius: 15px; margin: 20px; padding: 30px; box-shadow: 0 20px 40px rgba(0,0,0,0.1); }}
                .stat-card {{ background: linear-gradient(45deg, #ff6b6b, #4ecdc4); color: white; border-radius: 10px; padding: 20px; margin: 10px 0; }}
                .issue-card {{ border-left: 5px solid; margin: 10px 0; padding: 15px; }}
                .critical {{ border-color: #dc3545; background: #fff5f5; }}
                .high {{ border-color: #fd7e14; background: #fff8f0; }}
                .medium {{ border-color: #ffc107; background: #fffef0; }}
                .low {{ border-color: #28a745; background: #f0fff4; }}
                .chart-container {{ height: 300px; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <div class="main-container">
                <div class="text-center mb-4">
                    <h1 class="display-4">🕷️ SpiderIntel</h1>
                    <h2 class="text-muted">Analyse de Sécurité - {self.domain}</h2>
                    <p class="lead">Rapport basé sur les données réellement collectées</p>
                </div>
                
                <!-- Statistiques globales -->
                <div class="row">
                    <div class="col-md-3">
                        <div class="stat-card text-center">
                            <h3>{targets['total_targets']}</h3>
                            <p>Cibles Analysées</p>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card text-center">
                            <h3>{len(assets['subdomains']) + len(assets['ips'])}</h3>
                            <p>Assets Découverts</p>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card text-center">
                            <h3>{sum(len(p) for p in issues.values())}</h3>
                            <p>Problèmes Détectés</p>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="stat-card text-center">
                            <h3>{len(issues)}</h3>
                            <p>Catégories de Risques</p>
                        </div>
                    </div>
                </div>
                
                <!-- Graphiques des découvertes -->
                <div class="row mt-4">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-body">
                                <h5>Distribution des Problèmes par Sévérité</h5>
                                <div class="chart-container">
                                    <canvas id="severityChart"></canvas>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-body">
                                <h5>Assets Découverts</h5>
                                <div class="chart-container">
                                    <canvas id="assetsChart"></canvas>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Détails des problèmes par catégorie -->
                {self._generate_issue_cards_html(issues)}
                
                <!-- Cibles analysées -->
                <div class="card mt-4">
                    <div class="card-body">
                        <h5>🎯 Cibles Analysées</h5>
                        <div class="row">
                            <div class="col-md-6">
                                <h6>Adresses IP ({len(targets['scanned_ips'])})</h6>
                                <ul class="list-group">
                                    {self._generate_target_list_html(targets['scanned_ips'][:10])}
                                </ul>
                            </div>
                            <div class="col-md-6">
                                <h6>Domaines ({len(targets['scanned_domains'])})</h6>
                                <ul class="list-group">
                                    {self._generate_target_list_html(targets['scanned_domains'][:10])}
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <script>
                // Graphique des sévérités (seulement si des données)
                {f'''
                new Chart(document.getElementById('severityChart'), {{
                    type: 'doughnut',
                    data: {{
                        labels: {[k for k, v in severity_counts.items() if v > 0]},
                        datasets: [{{
                            data: {[v for v in severity_counts.values() if v > 0]},
                            backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745']
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false
                    }}
                }});
                ''' if any(severity_counts.values()) else ''}
                
                // Graphique des assets
                {f'''
                new Chart(document.getElementById('assetsChart'), {{
                    type: 'bar',
                    data: {{
                        labels: ['Sous-domaines', 'IPs', 'Emails', 'Technologies'],
                        datasets: [{{
                            data: [{len(assets['subdomains'])}, {len(assets['ips'])}, {len(assets['emails'])}, {len(assets['technologies'])}],
                            backgroundColor: ['#4ecdc4', '#45b7d1', '#96ceb4', '#ffeaa7']
                        }}]
                    }},
                    options: {{
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {{ legend: {{ display: false }} }}
                    }}
                }});
                '''}
            </script>
        </body>
        </html>
        """
        
        return html_template
    
    def _generate_issue_cards_html(self, issues):
        """Génère les cartes des problèmes de sécurité"""
        if not issues:
            return '<div class="alert alert-success mt-4"><h5>✅ Aucun problème de sécurité détecté</h5></div>'
        
        cards_html = '<div class="mt-4"><h4>🔍 Problèmes de Sécurité Détectés</h4>'
        
        for category, problems in issues.items():
            severity_class = problems[0]['severity'].lower()
            cards_html += f'''
            <div class="issue-card {severity_class}">
                <h6>{category} ({len(problems)} problème(s))</h6>
                <p>Sévérité: <span class="badge bg-{severity_class}">{problems[0]['severity']}</span></p>
            '''
            
            # Grouper les problèmes similaires
            problem_counts = {}
            for problem in problems:
                clean_name = problem['name'].split(' sur ')[0] if ' sur ' in problem['name'] else problem['name']
                if clean_name not in problem_counts:
                    problem_counts[clean_name] = {'count': 0, 'targets': set()}
                problem_counts[clean_name]['count'] += 1
                problem_counts[clean_name]['targets'].add(problem['target'])
            
            for problem_name, info in list(problem_counts.items())[:3]:  # Max 3 par catégorie
                if info['count'] > 1:
                    cards_html += f'<li>{problem_name} ({info["count"]} occurrences)</li>'
                else:
                    cards_html += f'<li>{problem_name}</li>'
            
            if len(problem_counts) > 3:
                cards_html += f'<li>... et {len(problem_counts) - 3} autres problèmes</li>'
            
            cards_html += '</div>'
        
        cards_html += '</div>'
        return cards_html
    
    def _generate_target_list_html(self, targets):
        """Génère la liste HTML des cibles"""
        return ''.join(f'<li class="list-group-item">{target}</li>' for target in targets)
    
    def generate_executive_summary(self, report_generator) -> str:
        """Génère un résumé exécutif basé sur les données réelles"""
        real_data = report_generator.real_data
        assets = real_data['collected_assets']
        targets = real_data['target_analysis'] 
        issues = real_data['security_issues']
        
        summary = f"""
SPIDERINTEL - RÉSUMÉ EXÉCUTIF
===============================
Domaine analysé: {self.domain}
Date d'analyse: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

SYNTHÈSE DES DÉCOUVERTES
------------------------
• Cibles analysées: {targets['total_targets']}
• Assets découverts: {len(assets['subdomains']) + len(assets['ips']) + len(assets['emails'])}
• Problèmes de sécurité: {len(report_generator.vulnerabilities)}
• Catégories de risques: {len(issues)}

NIVEAU DE RISQUE GLOBAL
-----------------------
"""
        
        # Calculer le niveau de risque
        high_risk_issues = sum(1 for problems in issues.values() 
                              for problem in problems 
                              if problem['severity'] in ['Critical', 'High'])
        
        if high_risk_issues > 10:
            summary += "🔴 CRITIQUE - Action immédiate requise\n"
        elif high_risk_issues > 5:
            summary += "🟠 ÉLEVÉ - Correction prioritaire recommandée\n"
        elif high_risk_issues > 0:
            summary += "🟡 MODÉRÉ - Planifier les corrections\n"
        else:
            summary += "🟢 FAIBLE - Surveillance continue recommandée\n"
        
        # Actions prioritaires
        summary += f"""
ACTIONS PRIORITAIRES
--------------------
"""
        
        if 'HTTP Security Headers' in issues:
            summary += f"1. Configurer les en-têtes de sécurité HTTP ({len(issues['HTTP Security Headers'])} problèmes)\n"
        
        if any('CVE' in category for category in issues.keys()):
            cve_count = sum(len(problems) for category, problems in issues.items() if 'CVE' in category)
            summary += f"2. Appliquer les correctifs de sécurité ({cve_count} CVE identifiées)\n"
        
        if 'SSL/TLS Configuration' in issues:
            summary += f"3. Réviser la configuration SSL/TLS ({len(issues['SSL/TLS Configuration'])} problèmes)\n"
        
        summary += f"""
COUVERTURE DU SCAN
------------------
• IPs scannées: {', '.join(targets['scanned_ips'][:3])}{'...' if len(targets['scanned_ips']) > 3 else ''}
• Domaines analysés: {len(targets['scanned_domains'])}
• Technologies identifiées: {len(assets['technologies'])}

RECOMMANDATIONS
---------------
1. Traiter en priorité les problèmes de sévérité élevée
2. Mettre en place une surveillance continue 
3. Planifier des scans réguliers (mensuel recommandé)
4. Former l'équipe aux bonnes pratiques de sécurité

---
Généré par SpiderIntel v2.0.0
Basé sur {len(report_generator.vulnerabilities)} découvertes de sécurité
"""
        
        return summary

def check_dependencies():
    """Vérifie les dépendances système"""
    logger.info("🔧 Vérification des dépendances...")
    
    required_tools = {
        'nmap': 'nmap',
        'whatweb': 'whatweb', 
        'theHarvester': 'theharvester',
        'dig': 'dnsutils'
    }
    
    missing_tools = []
    
    for tool, package in required_tools.items():
        try:
            subprocess.run(['which', tool], check=True, capture_output=True)
            logger.info(f"✅ {tool} trouvé")
        except subprocess.CalledProcessError:
            logger.warning(f"⚠️ {tool} manquant")
            missing_tools.append(package)
    
    if missing_tools:
        logger.error(f"❌ Outils manquants: {', '.join(missing_tools)}")
        logger.info("Installez-les avec: sudo apt install " + " ".join(missing_tools))
        return False
    
    logger.info("✅ Toutes les dépendances sont présentes")
    return True

def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(
        description="SpiderIntel v2.0.0 - Outil d'analyse de sécurité complet",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python spiderintel.py example.com
  python spiderintel.py example.com --output /tmp/reports
  python spiderintel.py example.com --check-deps

⚠️  AVERTISSEMENT LÉGAL:
Cet outil est destiné uniquement aux tests de sécurité autorisés.
N'utilisez cet outil que sur des systèmes dont vous êtes propriétaire
ou pour lesquels vous avez une autorisation écrite explicite.
        """
    )
    
    parser.add_argument('domain', help='Domaine cible à analyser')
    parser.add_argument('--output', '-o', default='reports', 
                       help='Répertoire de sortie des rapports (défaut: reports)')
    parser.add_argument('--check-deps', action='store_true',
                       help='Vérifier les dépendances seulement')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Mode verbeux')
    parser.add_argument('--scan-depth', choices=['quick', 'normal', 'deep'],
                       default='quick', help='Niveau de profondeur du scan (défaut: quick)')
    
    args = parser.parse_args()
    
    # Configuration du logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Affichage de la bannière
    print_banner()
    
    # Vérification des dépendances
    if not check_dependencies():
        if args.check_deps:
            sys.exit(1)
        logger.warning("⚠️ Certaines dépendances manquent, l'analyse peut être incomplète")
    
    if args.check_deps:
        logger.info("✅ Vérification des dépendances terminée")
        sys.exit(0)
    
    try:
        # Lancement de l'analyse
        spider_intel = SpiderIntelMain(args.domain, args.output, args.scan_depth)
        results = spider_intel.run_complete_analysis()
        
        logger.info("\n🎯 Analyse terminée avec succès!")
        logger.info("📋 Consultez les rapports générés pour les détails complets.")
        
    except KeyboardInterrupt:
        logger.info("\n⚠️ Analyse interrompue par l'utilisateur")
        sys.exit(1)
    except ValueError as e:
        logger.error(f"❌ Erreur de validation: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"❌ Erreur inattendue: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()