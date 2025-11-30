#!/usr/bin/env python3
"""
NetHawk Security Toolkit - Setup Script
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="nethawk",
    version="1.0.0",
    author="NetHawk Team",
    description="Next-Gen Packet & Path Intelligence Toolkit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/nethawk",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.7",
    install_requires=[
        "scapy>=2.4.5",
    ],
    entry_points={
        "console_scripts": [
            "nethawk=nethawk.cli:main",
        ],
    },
    include_package_data=True,
)
