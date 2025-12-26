#!/usr/bin/env python3
"""
Setup script for Advanced WAF Detector
"""

from setuptools import setup, find_packages
import os

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="advanced-waf-detector",
    version="2.0.0",
    author="Veerxx",
    author_email="",  # Add your email
    description="Advanced Web Application Firewall detection and fingerprinting tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Veerxx/advanced-waf-detector",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
    ],
    python_requires=">=3.7",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "waf-detector=waf_detector:main",
            "wafd=waf_detector:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["config/*.json", "docs/*.md"],
    },
    keywords=["security", "waf", "detection", "firewall", "cybersecurity"],
    project_urls={
        "Bug Reports": "https://github.com/Veerxx/advanced-waf-detector/issues",
        "Source": "https://github.com/Veerxx/advanced-waf-detector",
        "Documentation": "https://github.com/Veerxx/advanced-waf-detector/blob/main/docs/README.md",
    },
)
