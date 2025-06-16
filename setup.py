from setuptools import setup, find_packages

setup(
    name="spiderintel",
    version="1.0.0",
    author="XIS10CIAL",
    description="Outil OSINT avancé pour la collecte d'intelligence numérique.",
    packages=find_packages(),
    py_modules=["spiderintel"],
    install_requires=[
        "requests",
        "termcolor",
        "rich"
    ],
    entry_points={
        "console_scripts": [
            "spiderintel=spiderintel:main"
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security"
    ],
    python_requires=">=3.8",
) 