"""
Setup script for VMDragonSlayer refactored library.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the contents of README file
this_directory = Path(__file__).parent
long_description = (this_directory / "../README.md").read_text(encoding='utf-8')

# Read requirements
requirements = []
requirements_path = this_directory / "requirements.txt"
if requirements_path.exists():
    with open(requirements_path, 'r', encoding='utf-8') as f:
        requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="vmdragonslayer",
    version="2.0.0",
    author="van1sh",
    author_email="contact@vmdragonslayer.dev",
    description="Advanced VM detection and analysis library for binary reverse engineering",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/poppopjmp/vmdragonslayer",
    license="GPL-3.0",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Monitoring",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "mypy>=1.5.0",
            "ruff>=0.0.280",
        ],
        "web": [
            "fastapi>=0.100.0",
            "uvicorn[standard]>=0.23.0",
            "websockets>=11.0.0",
        ],
        "ml": [
            "scikit-learn>=1.3.0",
            "tensorflow>=2.13.0",
            "torch>=2.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "vmdragonslayer=vmdragonslayer.cli:main",
            "vmdslayer=vmdragonslayer.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "vmdragonslayer": [
            "data/*.json",
            "data/*.db",
            "templates/*.html",
            "static/*",
        ],
    },
    keywords=[
        "reverse-engineering",
        "binary-analysis", 
        "vm-detection",
        "malware-analysis",
        "security",
        "deobfuscation",
        "pattern-analysis",
        "symbolic-execution",
    ],
    project_urls={
        "Bug Reports": "https://github.com/poppopjmp/vmdragonslayer/issues",
        "Source": "https://github.com/poppopjmp/vmdragonslayer",
        "Documentation": "https://vmdragonslayer.readthedocs.io/",
    },
)
