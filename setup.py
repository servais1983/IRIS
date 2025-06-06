#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script d'installation pour IRIS.
"""

import os
import sys
from setuptools import setup, find_packages

# Définir les dépendances
REQUIRED_PACKAGES = [
    "cryptography>=41.0.7",
    "cffi>=1.15.1",
    "pycparser>=2.21",
    "schedule>=1.2.1",
    "qrcode>=8.2",
    "pillow>=11.2.1",
    "pyotp>=2.9.0",
    "redis>=5.0.1",
    "elasticsearch>=8.11.0",
    "requests>=2.31.0",
    "pyyaml>=6.0.1",
    "bleach>=6.1.0",
    "jsonschema>=4.21.1",
    "sqlparse>=0.4.4",
    "twilio>=8.10.0",
    "boto3>=1.34.0",
    "hvac>=1.2.0",
    "setuptools>=68.0.0",
    "wheel>=0.41.0"
]

# Définir les packages de développement
DEV_PACKAGES = [
    "pytest>=7.4.0",
    "pytest-cov>=4.1.0",
    "pytest-mock>=3.10.0",
    "pytest-asyncio>=0.21.0",
    "pytest-xdist>=3.3.1",
    "pytest-timeout>=2.1.0",
    "pytest-env>=1.0.0",
    "pytest-sugar>=0.9.7",
    "pytest-html>=3.2.0",
    "pytest-metadata>=3.0.0",
    "pytest-ordering>=0.6.0",
    "pytest-randomly>=3.12.0",
    "pytest-repeat>=0.9.1",
    "pytest-rerunfailures>=11.1.2",
    "pytest-selenium>=4.0.0",
    "pytest-vcr>=1.0.2",
    "pytest-watch>=4.2.0",
    "pytest-xprocess>=0.22.0",
    "pytest-xvfb>=3.0.0",
    "coverage>=7.3.0",
    "black>=23.0.0",
    "isort>=5.12.0",
    "mypy>=1.0.0",
    "pylint>=2.17.0",
    "flake8>=6.0.0"
]

def create_directories():
    """Crée les répertoires nécessaires pour l'installation."""
    os.makedirs("/var/log/iris", exist_ok=True)
    os.makedirs("/etc/iris", exist_ok=True)

# Vérifier la version de Python
if sys.version_info < (3, 8):
    raise RuntimeError("IRIS nécessite Python 3.8 ou supérieur")

# Créer les répertoires nécessaires
create_directories()

setup(
    name="iris",
    version="0.1.0",
    description="IRIS - Outil d'investigation et de réponse aux incidents",
    author="IRIS Team",
    author_email="contact@iris.example.com",
    url="https://github.com/iris-team/iris",
    packages=find_packages(),
    install_requires=REQUIRED_PACKAGES,
    extras_require={
        "dev": DEV_PACKAGES
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Systems Administration"
    ],
    entry_points={
        "console_scripts": [
            "iris=iris:main"
        ]
    }
) 