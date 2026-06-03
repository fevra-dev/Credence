"""Setup script for GitExpose."""

from setuptools import setup, find_packages

setup(
    name="credence",
    version="0.4.0",
    description="Exposure intelligence for AI and dev infrastructure — credential, AI-tool config, and supply-chain detection",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="GitExpose Contributors",
    license="MIT",
    packages=find_packages(),
    package_data={"credence": ["data/*.json"]},
    include_package_data=True,
    python_requires=">=3.9",
    install_requires=[
        "aiohttp>=3.9.0",
        "click>=8.1.0",
        "colorama>=0.4.6",
        "httpx>=0.27.0",
        "PyYAML>=6.0",
    ],
    extras_require={
        "advanced": [
            "aiofiles>=23.2.0",
            "GitPython>=3.1.40",
            "rich>=13.7.0",
            "python-magic>=0.4.27",
        ],
        "cloud": [
            "boto3>=1.34.0",
            "google-cloud-compute>=1.19.0",
            "azure-mgmt-compute>=30.0.0",
        ],
        "full": [
            "aiofiles>=23.2.0",
            "GitPython>=3.1.40",
            "rich>=13.7.0",
            "boto3>=1.34.0",
            "shodan>=1.31.0",
        ],
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "aioresponses>=0.7.4",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "respx>=0.21.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "credence=credence.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
    keywords=[
        "security",
        "scanner", 
        "pentesting",
        "git",
        "vulnerability",
        "CVE-2025-55182",
        "react2shell",
        "ml-security",
    ],
)
