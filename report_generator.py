import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass

@dataclass
class OSINTResult:
    subdomains: set
    emails: set
    ips: set
    technologies: set
    ports: Dict
    certificates: Dict
    social_media: set

@dataclass
class VulnerabilityResult:
    name: str
    severity: str
    description: str
    cvss_score: float
    mitigation: str

class ReportGenerator:
    """Générateur de rapports complets"""
    
    def __init__(self, domain: str, osint_results: OSINTResult, 
                 vulnerabilities: List[VulnerabilityResult], 
                 exploit_suggestions: List[Dict[str, Any]]):
        self.domain = domain
        self.osint_results = osint_results
        self.vulnerabilities = vulnerabilities
        self.exploit_suggestions = exploit_suggestions
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        # Templates pour le rapport HTML
        self.html_template = """
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>SpiderIntel - Rapport d'Analyse</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
                .card { margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                .chart-container { position: relative; height: 400px; margin: 20px 0; }
                .vulnerability-high { background-color: #ffebee; }
                .vulnerability-medium { background-color: #fff3e0; }
                .vulnerability-low { background-color: #e8f5e9; }
            </style>
        </head>
        <body>
            <div class="container-fluid py-4">
                <h1 class="text-center mb-4">🕷️ SpiderIntel - Rapport d'Analyse</h1>
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
                                            {vulnerabilities_table}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="row">
                    <div class="col-md-12">
                        <div class="card">
                            <div class="card-body">
                                <h2>💡 Suggestions d'Exploitation</h2>
                                <div class="table-responsive">
                                    <table class="table table-striped">
                                        <thead>
                                            <tr>
                                                <th>Vulnérabilité</th>
                                                <th>Méthode</th>
                                                <th>Commandes</th>
                                                <th>Risque</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {exploits_table}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <script>
                // Graphique de résumé
                new Chart(document.getElementById('summaryChart'), {
                    type: 'bar',
                    data: {
                        labels: ['Sous-domaines', 'IPs', 'Emails', 'Technologies', 'Vulnérabilités'],
                        datasets: [{
                            label: 'Découvertes',
                            data: {summary_data},
                            backgroundColor: [
                                'rgba(54, 162, 235, 0.8)',
                                'rgba(255, 99, 132, 0.8)',
                                'rgba(75, 192, 192, 0.8)',
                                'rgba(255, 206, 86, 0.8)',
                                'rgba(153, 102, 255, 0.8)'
                            ]
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            title: {
                                display: true,
                                text: 'Résumé des Découvertes'
                            }
                        }
                    }
                });
                
                // Graphique des vulnérabilités
                new Chart(document.getElementById('vulnerabilityChart'), {
                    type: 'pie',
                    data: {
                        labels: ['Critique', 'Haute', 'Moyenne', 'Basse'],
                        datasets: [{
                            data: {vulnerability_data},
                            backgroundColor: [
                                'rgba(255, 0, 0, 0.8)',
                                'rgba(255, 165, 0, 0.8)',
                                'rgba(255, 255, 0, 0.8)',
                                'rgba(0, 255, 0, 0.8)'
                            ]
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            title: {
                                display: true,
                                text: 'Distribution des Vulnérabilités'
                            }
                        }
                    }
                });
                
                // Graphique OSINT
                new Chart(document.getElementById('osintChart'), {
                    type: 'doughnut',
                    data: {
                        labels: ['Sous-domaines', 'IPs', 'Emails'],
                        datasets: [{
                            data: {osint_data},
                            backgroundColor: [
                                'rgba(54, 162, 235, 0.8)',
                                'rgba(255, 99, 132, 0.8)',
                                'rgba(75, 192, 192, 0.8)'
                            ]
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            title: {
                                display: true,
                                text: 'Découvertes OSINT'
                            }
                        }
                    }
                });
                
                // Graphique des technologies
                new Chart(document.getElementById('techChart'), {
                    type: 'horizontalBar',
                    data: {
                        labels: {tech_labels},
                        datasets: [{
                            label: 'Technologies',
                            data: {tech_data},
                            backgroundColor: 'rgba(75, 192, 192, 0.8)'
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            title: {
                                display: true,
                                text: 'Technologies Détectées'
                            }
                        }
                    }
                });
            </script>
        </body>
        </html>
        """
    
    def generate_html_report(self) -> str:
        """Génère un rapport HTML complet avec graphiques"""
        # Préparation des données pour les graphiques
        summary_data = [
            len(self.osint_results.subdomains),
            len(self.osint_results.ips),
            len(self.osint_results.emails),
            len(self.osint_results.technologies),
            len(self.vulnerabilities)
        ]
        
        # Distribution des vulnérabilités
        vuln_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for vuln in self.vulnerabilities:
            vuln_counts[vuln.severity] = vuln_counts.get(vuln.severity, 0) + 1
        
        vulnerability_data = [
            vuln_counts['Critical'],
            vuln_counts['High'],
            vuln_counts['Medium'],
            vuln_counts['Low']
        ]
        
        # Données OSINT
        osint_data = [
            len(self.osint_results.subdomains),
            len(self.osint_results.ips),
            len(self.osint_results.emails)
        ]
        
        # Technologies
        tech_labels = list(self.osint_results.technologies)
        tech_data = [1] * len(tech_labels)
        
        # Table des vulnérabilités
        vulnerabilities_rows = []
        for vuln in self.vulnerabilities:
            row = f"""
            <tr class="vulnerability-{vuln.severity.lower()}">
                <td>{vuln.name}</td>
                <td>{vuln.severity}</td>
                <td>{vuln.description}</td>
                <td>{vuln.cvss_score}</td>
                <td>{vuln.mitigation}</td>
            </tr>
            """
            vulnerabilities_rows.append(row)
        
        # Table des exploits
        exploits_rows = []
        for exploit in self.exploit_suggestions:
            row = f"""
            <tr>
                <td>{exploit['vulnerability']}</td>
                <td>{exploit['method']}</td>
                <td><pre>{exploit['commands']}</pre></td>
                <td>{exploit['risk_level']}</td>
            </tr>
            """
            exploits_rows.append(row)
        
        # Génération du rapport HTML
        html_report = self.html_template.format(
            summary_data=summary_data,
            vulnerability_data=vulnerability_data,
            osint_data=osint_data,
            tech_labels=tech_labels,
            tech_data=tech_data,
            vulnerabilities_table='\n'.join(vulnerabilities_rows),
            exploits_table='\n'.join(exploits_rows)
        )
        
        return html_report
    
    def generate_markdown_report(self) -> str:
        """Génère un rapport Markdown complet"""
        report = []
        
        # En-tête
        report.append("# 🕷️ SpiderIntel - Rapport d'Analyse Complet")
        report.append(f"**Domaine cible:** {self.domain}")
        report.append(f"**Date d'analyse:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"**Version:** SpiderIntel v2.0.0")
        report.append("\n" + "="*80 + "\n")
        
        # Résumé exécutif
        report.append("## 📊 Résumé Exécutif")
        report.append(f"- **Sous-domaines découverts:** {len(self.osint_results.subdomains)}")
        report.append(f"- **Adresses IP identifiées:** {len(self.osint_results.ips)}")
        report.append(f"- **Emails trouvés:** {len(self.osint_results.emails)}")
        report.append(f"- **Technologies détectées:** {len(self.osint_results.technologies)}")
        report.append(f"- **Vulnérabilités identifiées:** {len(self.vulnerabilities)}")
        report.append(f"- **Suggestions d'exploitation:** {len(self.exploit_suggestions)}")
        
        # Découvertes OSINT
        report.append("\n## 🔍 Découvertes OSINT")
        
        if self.osint_results.subdomains:
            report.append("\n### Sous-domaines")
            for subdomain in sorted(self.osint_results.subdomains):
                report.append(f"- {subdomain}")
        
        if self.osint_results.ips:
            report.append("\n### Adresses IP")
            for ip in sorted(self.osint_results.ips):
                report.append(f"- {ip}")
        
        if self.osint_results.emails:
            report.append("\n### Emails")
            for email in sorted(self.osint_results.emails):
                report.append(f"- {email}")
        
        if self.osint_results.technologies:
            report.append("\n### Technologies")
            for tech in sorted(self.osint_results.technologies):
                report.append(f"- {tech}")
        
        # Vulnérabilités
        report.append("\n## ⚠️ Vulnérabilités")
        for vuln in self.vulnerabilities:
            report.append(f"\n### {vuln.name}")
            report.append(f"- **Sévérité:** {vuln.severity}")
            report.append(f"- **Description:** {vuln.description}")
            report.append(f"- **Score CVSS:** {vuln.cvss_score}")
            report.append(f"- **Mitigation:** {vuln.mitigation}")
        
        # Suggestions d'exploitation
        report.append("\n## 💡 Suggestions d'Exploitation")
        for exploit in self.exploit_suggestions:
            report.append(f"\n### {exploit['vulnerability']}")
            report.append(f"- **Méthode:** {exploit['method']}")
            report.append(f"- **Commandes:**")
            report.append("```bash")
            report.append(exploit['commands'])
            report.append("```")
            report.append(f"- **Niveau de risque:** {exploit['risk_level']}")
        
        return "\n".join(report)
    
    def save_reports(self, output_dir: Path) -> Dict[str, Path]:
        """Sauvegarde les rapports dans différents formats"""
        output_dir.mkdir(parents=True, exist_ok=True)
        saved_files = {}
        
        # Rapport Markdown
        md_report = self.generate_markdown_report()
        md_path = output_dir / f"spiderintel_report_{self.timestamp}.md"
        md_path.write_text(md_report, encoding='utf-8')
        saved_files['markdown'] = md_path
        
        # Rapport HTML
        html_report = self.generate_html_report()
        html_path = output_dir / f"spiderintel_report_{self.timestamp}.html"
        html_path.write_text(html_report, encoding='utf-8')
        saved_files['html'] = html_path
        
        # Rapport JSON
        json_data = {
            'domain': self.domain,
            'timestamp': self.timestamp,
            'osint_results': {
                'subdomains': list(self.osint_results.subdomains),
                'ips': list(self.osint_results.ips),
                'emails': list(self.osint_results.emails),
                'technologies': list(self.osint_results.technologies),
                'ports': self.osint_results.ports,
                'certificates': self.osint_results.certificates,
                'social_media': list(self.osint_results.social_media)
            },
            'vulnerabilities': [
                {
                    'name': v.name,
                    'severity': v.severity,
                    'description': v.description,
                    'cvss_score': v.cvss_score,
                    'mitigation': v.mitigation
                }
                for v in self.vulnerabilities
            ],
            'exploit_suggestions': self.exploit_suggestions
        }
        
        json_path = output_dir / f"spiderintel_report_{self.timestamp}.json"
        json_path.write_text(json.dumps(json_data, indent=2), encoding='utf-8')
        saved_files['json'] = json_path
        
        return saved_files 