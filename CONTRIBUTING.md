# Contribution

## Principes

Les contributions doivent servir des usages défensifs, légaux et explicitement autorisés. Elles ne doivent pas supprimer la validation des cibles ni la confirmation `--authorized`.

## Environnement

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Vérifications

Avant d’ouvrir une pull request :

```bash
python -m ruff check spiderintel.py report_generator.py tests
python -m pytest --cov=spiderintel --cov-report=term-missing
python -m pip check
```

Pour les changements touchant les adaptateurs d’outils externes, exécutez également le smoke test Kali documenté dans le README. La cible Metasploit est requise lorsque son générateur ou son parseur est modifié.

Chaque correction fonctionnelle doit inclure un test de non-régression. Les changements liés aux outils Kali doivent préciser les versions testées et les commandes exécutées.

## Pull requests

Une pull request doit rester ciblée, décrire l’impact opérationnel et signaler les limites connues. Ne commitez jamais de clé API, de rapport réel, de donnée personnelle ou d’information issue d’une mission client.
