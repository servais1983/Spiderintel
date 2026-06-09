#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SpiderIntel v2.0.0 - Script de test et validation
Teste les principales fonctionnalités de SpiderIntel
"""

import sys
import os
import unittest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock
import json

# Ajouter le répertoire parent au path pour importer spiderintel
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from spiderintel import (
        SecurityValidator, 
        OSINTScanner, 
        VulnerabilityScanner, 
        ExploitSuggester,
        ReportGenerator,
        SpiderIntelMain,
        OSINTResult,
        VulnerabilityResult
    )
except ImportError as e:
    raise RuntimeError("Impossible d'importer SpiderIntel") from e

class TestSecurityValidator(unittest.TestCase):
    """Tests pour SecurityValidator"""
    
    def setUp(self):
        self.validator = SecurityValidator()
    
    def test_validate_domain(self):
        """Test de validation des domaines"""
        # Domaines valides
        self.assertTrue(self.validator.validate_domain("example.com"))
        self.assertTrue(self.validator.validate_domain("sub.example.com"))
        self.assertTrue(self.validator.validate_domain("test-site.example.org"))
        
        # Domaines invalides
        self.assertFalse(self.validator.validate_domain(""))
        self.assertFalse(self.validator.validate_domain("invalid"))
        self.assertFalse(self.validator.validate_domain("..example.com"))
        self.assertFalse(self.validator.validate_domain("example..com"))
    
    def test_validate_ip(self):
        """Test de validation des adresses IP"""
        # IPs valides
        self.assertTrue(self.validator.validate_ip("192.168.1.1"))
        self.assertTrue(self.validator.validate_ip("8.8.8.8"))
        self.assertTrue(self.validator.validate_ip("127.0.0.1"))
        
        # IPs invalides
        self.assertFalse(self.validator.validate_ip("256.1.1.1"))
        self.assertFalse(self.validator.validate_ip("192.168.1"))
        self.assertFalse(self.validator.validate_ip("not.an.ip.address"))

    def test_normalize_target(self):
        self.assertEqual(self.validator.normalize_target(" Example.COM. "), "example.com")
        self.assertEqual(self.validator.normalize_target("192.0.2.10"), "192.0.2.10")

        with self.assertRaises(ValueError):
            self.validator.normalize_target("https://example.com/path")

        with self.assertRaises(ValueError):
            self.validator.normalize_target("example.com:443")
    
    def test_validate_email(self):
        """Test de validation des emails"""
        # Emails valides
        self.assertTrue(self.validator.validate_email("test@example.com"))
        self.assertTrue(self.validator.validate_email("user.name@domain.org"))
        
        # Emails invalides
        self.assertFalse(self.validator.validate_email("invalid-email"))
        self.assertFalse(self.validator.validate_email("@example.com"))
        self.assertFalse(self.validator.validate_email("test@"))

class TestOSINTScanner(unittest.TestCase):
    """Tests pour OSINTScanner"""
    
    def setUp(self):
        self.scanner = OSINTScanner("example.com")
    
    def test_clean_domain(self):
        """Test du nettoyage des domaines"""
        test_cases = [
            ("http://example.com", "example.com"),
            ("https://www.example.com/path", "www.example.com"),
            ("example.com:8080", "example.com"),
            ("EXAMPLE.COM", "example.com")
        ]
        
        for input_domain, expected in test_cases:
            with self.subTest(input_domain=input_domain):
                result = self.scanner.clean_domain(input_domain)
                self.assertEqual(result, expected)
    
    def test_get_root_domain(self):
        """Test d'extraction du domaine racine"""
        test_cases = [
            ("www.example.com", "example.com"),
            ("sub.domain.example.org", "example.org"),
            ("test.example.co.uk", "example.co.uk")
        ]
        
        for input_domain, expected in test_cases:
            with self.subTest(input_domain=input_domain):
                result = self.scanner.get_root_domain(input_domain)
                self.assertEqual(result, expected)
    
    @patch('requests.Session.get')
    def test_scan_crtsh(self, mock_get):
        """Test du scan crt.sh"""
        # Mock de la réponse crt.sh
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                'name_value': 'www.example.com\nsub.example.com',
                'issuer_name': 'Let\'s Encrypt',
                'not_before': '2025-01-01',
                'not_after': '2025-12-31'
            }
        ]
        mock_get.return_value = mock_response
        
        self.scanner.scan_crtsh()
        
        # Vérifier que des sous-domaines ont été trouvés
        self.assertGreater(len(self.scanner.results.subdomains), 0)
        self.assertIn('www.example.com', self.scanner.results.subdomains)
        self.assertIn('sub.example.com', self.scanner.results.subdomains)

class TestVulnerabilityScanner(unittest.TestCase):
    """Tests pour VulnerabilityScanner"""
    
    def setUp(self):
        # Créer des résultats OSINT factices
        self.osint_results = OSINTResult(
            subdomains={'www.example.com', 'api.example.com'},
            emails={'admin@example.com'},
            ips={'192.168.1.1', '10.0.0.1'},
            technologies={'Apache/2.4.41', 'PHP/7.4'},
            ports={},
            certificates={},
            social_media=set()
        )
        self.scanner = VulnerabilityScanner(self.osint_results)
    
    def test_parse_nmap_vulnerabilities(self):
        """Test du parsing des résultats Nmap"""
        nmap_output = """
        |_http-vuln-cve2017-1001000: CVE-2017-1001000
        |   VULNERABLE:
        |   Apache HTTP Server vulnerable to CVE-2017-1001000
        """
        
        self.scanner.parse_nmap_vulnerabilities(nmap_output, "192.168.1.1")
        
        # Vérifier qu'une vulnérabilité a été détectée
        self.assertGreater(len(self.scanner.vulnerabilities), 0)
        
        # Vérifier les détails de la vulnérabilité
        vuln = self.scanner.vulnerabilities[0]
        self.assertIn("CVE-2017-1001000", vuln.cve_id)

class TestExploitSuggester(unittest.TestCase):
    """Tests pour ExploitSuggester"""
    
    def setUp(self):
        # Créer des vulnérabilités factices
        self.vulnerabilities = [
            VulnerabilityResult(
                name="Apache vulnerability detected",
                severity="High",
                description="Apache HTTP Server vulnerable to CVE-2017-1001000",
                cvss_score=8.0,
                cve_id="CVE-2017-1001000"
            ),
            VulnerabilityResult(
                name="SSH service detected",
                severity="Medium",
                description="SSH service running on port 22",
                cvss_score=5.0
            )
        ]
        self.suggester = ExploitSuggester(self.vulnerabilities)
    
    def test_generate_exploit_suggestions(self):
        """Test de génération des suggestions d'exploitation"""
        suggestions = self.suggester.generate_exploit_suggestions()
        
        # Vérifier qu'au moins une suggestion a été générée
        self.assertGreater(len(suggestions), 0)
        
        # Vérifier la structure des suggestions
        suggestion = suggestions[0]
        required_keys = ['vulnerability', 'severity', 'tools', 'techniques', 'commands', 'precautions', 'legal_notice']
        for key in required_keys:
            self.assertIn(key, suggestion)

class TestReportGenerator(unittest.TestCase):
    """Tests pour ReportGenerator"""
    
    def setUp(self):
        # Créer des données factices
        self.osint_results = OSINTResult(
            subdomains={'www.example.com', 'api.example.com'},
            emails={'admin@example.com'},
            ips={'192.168.1.1'},
            technologies={'Apache/2.4.41'},
            ports={},
            certificates={},
            social_media={'twitter: https://twitter.com/example'}
        )
        
        self.vulnerabilities = [
            VulnerabilityResult(
                name="Missing security header",
                severity="Medium",
                description="X-Frame-Options header missing",
                cvss_score=5.0,
                mitigation="Add X-Frame-Options header"
            )
        ]
        
        self.exploit_suggestions = [
            {
                'vulnerability': 'Apache vulnerability',
                'severity': 'High',
                'service': 'apache',
                'tools': ['nikto', 'dirb'],
                'techniques': ['Directory traversal'],
                'commands': ['nikto -h TARGET'],
                'payloads': ['../../../etc/passwd'],
                'precautions': ['Get authorization first'],
                'legal_notice': 'Use only on authorized systems'
            }
        ]
        
        self.generator = ReportGenerator(
            "example.com",
            self.osint_results,
            self.vulnerabilities,
            self.exploit_suggestions
        )
    
    def test_calculate_risk_level(self):
        """Test du calcul du niveau de risque"""
        # Test avec des vulnérabilités de sévérité moyenne
        risk_level = self.generator.calculate_risk_level()
        self.assertIn(risk_level, ['Low', 'Medium', 'High', 'Critical'])
    
    def test_generate_comprehensive_report(self):
        """Test de génération du rapport complet"""
        report = self.generator.generate_comprehensive_report()
        
        # Vérifier que le rapport contient les sections attendues
        self.assertIn("SpiderIntel - Rapport d'Analyse Complet", report)
        self.assertIn("Résumé Exécutif", report)
        self.assertIn("Découvertes OSINT", report)
        self.assertIn("Vulnérabilités Identifiées", report)
        self.assertIn("Suggestions d'Exploitation", report)
        self.assertIn("Recommandations de Sécurité", report)
    
    def test_save_reports(self):
        """Test de sauvegarde des rapports"""
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir)
            saved_files = self.generator.save_reports(output_dir)
            
            # Vérifier que les fichiers ont été créés
            self.assertIn('main_report', saved_files)
            self.assertIn('json_report', saved_files)
            
            # Vérifier que les fichiers existent
            self.assertTrue(saved_files['main_report'].exists())
            self.assertTrue(saved_files['json_report'].exists())
            
            # Vérifier le contenu JSON
            with open(saved_files['json_report'], 'r') as f:
                json_data = json.load(f)
                self.assertEqual(json_data['domain'], 'example.com')
                self.assertIn('osint_results', json_data)
                self.assertIn('vulnerabilities', json_data)

class TestSpiderIntelMain(unittest.TestCase):
    """Tests pour la classe principale SpiderIntelMain"""
    
    def test_domain_validation(self):
        """Test de validation du domaine à l'initialisation"""
        # Domaine valide
        try:
            spider = SpiderIntelMain("example.com")
            self.assertEqual(spider.domain, "example.com")
        except ValueError:
            self.fail("La validation du domaine valide a échoué")
        
        # Domaine invalide
        with self.assertRaises(ValueError):
            SpiderIntelMain("invalid-domain")

    def test_authorization_is_required(self):
        spider = SpiderIntelMain("example.com")
        with self.assertRaises(PermissionError):
            spider.run_complete_analysis()

class TestIntegration(unittest.TestCase):
    """Tests d'intégration"""
    
    @patch('subprocess.run')
    @patch('requests.Session.get')
    def test_full_workflow_mock(self, mock_get, mock_subprocess):
        """Test du workflow complet avec mocks"""
        # Configuration des mocks
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = []
        mock_response.headers = {}
        mock_response.text = "Mock response"
        mock_get.return_value = mock_response
        
        mock_subprocess.return_value = MagicMock(
            returncode=0,
            stdout="Mock output",
            stderr=""
        )
        
        # Test avec un domaine fictif
        with tempfile.TemporaryDirectory() as temp_dir:
            spider = SpiderIntelMain("test.example.com", temp_dir, authorized=True)
            
            # Note: Ce test ne fonctionnera que si tous les outils sont mockés
            # Dans un environnement de test réel, vous voudriez mocker plus de composants
            try:
                results = spider.run_complete_analysis()
                self.assertIn('osint_results', results)
                self.assertIn('vulnerabilities', results)
                self.assertIn('exploit_suggestions', results)
            except Exception as e:
                # En cas d'erreur, vérifier que c'est dû aux dépendances manquantes
                self.assertIn("command not found", str(e).lower() + 
                            "dependencies missing" if "not found" not in str(e).lower() else str(e).lower())

def run_dependency_check():
    """Vérifie les dépendances système"""
    print("\n🔧 Vérification des dépendances...")
    
    required_tools = ['nmap', 'whatweb', 'theharvester', 'dig', 'whois']
    missing_tools = []
    
    import subprocess
    
    for tool in required_tools:
        try:
            subprocess.run(['which', tool], check=True, capture_output=True)
            print(f"✅ {tool}: trouvé")
        except subprocess.CalledProcessError:
            print(f"❌ {tool}: manquant")
            missing_tools.append(tool)
    
    if missing_tools:
        print(f"\n⚠️  Outils manquants: {', '.join(missing_tools)}")
        print("Installez-les avec: sudo apt install " + " ".join(missing_tools))
        return False
    else:
        print("\n✅ Toutes les dépendances système sont présentes")
        return True

def run_python_dependencies_check():
    """Vérifie les dépendances Python"""
    print("\n🐍 Vérification des dépendances Python...")
    
    required_modules = [
        'requests', 'beautifulsoup4', 'dnspython', 'whois', 'tldextract',
        'networkx', 'matplotlib', 'tqdm', 'colorama', 'termcolor', 'psutil'
    ]
    
    missing_modules = []
    
    for module in required_modules:
        try:
            # Adapter les noms de modules pour l'import
            import_name = module
            if module == 'beautifulsoup4':
                import_name = 'bs4'
            elif module == 'dnspython':
                import_name = 'dns'
            elif module == 'python-whois':
                import_name = 'whois'
            
            __import__(import_name)
            print(f"✅ {module}: importé avec succès")
        except ImportError:
            print(f"❌ {module}: manquant")
            missing_modules.append(module)
    
    if missing_modules:
        print(f"\n⚠️  Modules Python manquants: {', '.join(missing_modules)}")
        print("Installez-les avec: pip install " + " ".join(missing_modules))
        return False
    else:
        print("\n✅ Toutes les dépendances Python sont présentes")
        return True

def run_quick_functionality_test():
    """Test rapide des fonctionnalités principales"""
    print("\n🚀 Test rapide des fonctionnalités...")
    
    try:
        # Test de validation
        validator = SecurityValidator()
        assert validator.validate_domain("example.com"), "Validation de domaine échouée"
        assert validator.validate_ip("192.168.1.1"), "Validation d'IP échouée"
        assert validator.validate_email("test@example.com"), "Validation d'email échouée"
        print("✅ SecurityValidator: OK")
        
        # Test OSINT Scanner
        scanner = OSINTScanner("example.com")
        assert scanner.domain == "example.com", "Initialisation OSINTScanner échouée"
        assert scanner.clean_domain("https://www.example.com/") == "www.example.com", "Nettoyage de domaine échoué"
        print("✅ OSINTScanner: OK")
        
        # Test VulnerabilityResult
        vuln = VulnerabilityResult(
            name="Test vuln",
            severity="High",
            description="Test description",
            cvss_score=8.0
        )
        assert vuln.name == "Test vuln", "VulnerabilityResult échoué"
        print("✅ VulnerabilityResult: OK")
        
        # Test OSINTResult
        osint_result = OSINTResult(
            subdomains=set(),
            emails=set(),
            ips=set(),
            technologies=set(),
            ports={},
            certificates={},
            social_media=set()
        )
        assert isinstance(osint_result.subdomains, set), "OSINTResult échoué"
        print("✅ OSINTResult: OK")
        
        print("\n✅ Tous les tests de fonctionnalité de base réussis!")
        return True
        
    except Exception as e:
        print(f"\n❌ Test de fonctionnalité échoué: {e}")
        return False

def main():
    """Fonction principale de test"""
    print("🕷️  SpiderIntel v2.0.0 - Suite de Tests et Validation")
    print("=" * 60)
    
    # Vérifications des dépendances
    deps_ok = run_dependency_check()
    python_deps_ok = run_python_dependencies_check()
    
    # Tests de fonctionnalité rapide
    func_test_ok = run_quick_functionality_test()
    
    if not func_test_ok:
        print("\n❌ Les tests de fonctionnalité de base ont échoué")
        print("Vérifiez l'installation et les imports")
        return 1
    
    # Tests unitaires
    print("\n🧪 Exécution des tests unitaires...")
    
    # Découvrir et exécuter tous les tests
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Résumé final
    print("\n" + "=" * 60)
    print("📊 RÉSUMÉ DES TESTS")
    print("=" * 60)
    
    if deps_ok:
        print("✅ Dépendances système: OK")
    else:
        print("⚠️  Dépendances système: Partielles")
    
    if python_deps_ok:
        print("✅ Dépendances Python: OK")
    else:
        print("❌ Dépendances Python: Manquantes")
    
    if result.wasSuccessful():
        print("✅ Tests unitaires: RÉUSSIS")
        print(f"   - Tests exécutés: {result.testsRun}")
        print(f"   - Erreurs: {len(result.errors)}")
        print(f"   - Échecs: {len(result.failures)}")
    else:
        print("❌ Tests unitaires: ÉCHOUÉS")
        print(f"   - Tests exécutés: {result.testsRun}")
        print(f"   - Erreurs: {len(result.errors)}")
        print(f"   - Échecs: {len(result.failures)}")
    
    # Recommandations
    print("\n📋 RECOMMANDATIONS:")
    
    if not deps_ok:
        print("1. Installez les dépendances système manquantes")
        print("   sudo apt install nmap whatweb theharvester dnsutils whois")
    
    if not python_deps_ok:
        print("2. Installez les dépendances Python manquantes")
        print("   pip install -r requirements.txt")
    
    if result.wasSuccessful() and deps_ok and python_deps_ok:
        print("🎉 SpiderIntel est prêt à l'utilisation!")
        print("   Lancez: python3 spiderintel.py example.com")
    else:
        print("🔧 Corrigez les problèmes ci-dessus avant utilisation")
    
    return 0 if result.wasSuccessful() else 1

if __name__ == '__main__':
    exit_code = main()
    sys.exit(exit_code)
