#!/usr/bin/env python3
# ============================================================================
# SysVoidScan - Setup Configuration
# ============================================================================

from setuptools import setup, find_packages
from pathlib import Path

this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8") if (this_directory / "README.md").exists() else ""

setup(
    name="sysvoidscan",
    version="3.0.0",
    author="afsh4ck",
    author_email="afsh4ck@users.noreply.github.com",
    description="Web Security Testing Scanner - Modular Edition",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/afsh4ck/sysvoidscan",
    python_requires=">=3.8",
    packages=find_packages(),
    install_requires=[
        "requests>=2.28.0",
        "beautifulsoup4>=4.11.0",
        "colorama>=0.4.6",
        "tqdm>=4.64.0",
        "rich>=13.0.0",
        "pyyaml>=6.0",
    ],
    entry_points={
        "console_scripts": [
            "sysvoidscan=main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
    ],
    keywords="security scanning web vulnerability assessment",
)
