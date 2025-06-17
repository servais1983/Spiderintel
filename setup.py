from setuptools import setup, find_packages

setup(
    name="spiderintel",
    version="2.0.0",
    description="Outil d'analyse de sécurité pour Kali Linux",
    author="SpiderIntel Team",
    packages=find_packages(),
    install_requires=[
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.2",
        "dnspython>=2.4.2",
        "python-whois>=0.8.0",
        "tldextract>=3.4.4",
        "pandas>=2.0.3",
        "networkx>=3.1",
        "matplotlib>=3.7.1",
        "tqdm>=4.65.0",
        "colorama>=0.4.6",
        "termcolor>=2.3.0",
        "rich>=13.4.2",
        "cryptography>=41.0.3",
        "psutil>=5.9.5",
        "python-dotenv>=1.0.0",
        "validators>=0.22.0",
        "packaging>=23.1",
        "pyOpenSSL>=23.2.0",
        "pycryptodome>=3.19.0",
        "jinja2>=3.1.2",
        "markdown>=3.4.3",
        "pyyaml>=6.0.1"
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "spiderintel=spiderintel:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.8",
        "Topic :: Security",
    ],
) 