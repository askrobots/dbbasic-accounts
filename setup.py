from setuptools import setup, find_packages

setup(
    name="dbbasic-accounts",
    version="0.1.1",
    description="Unix-style user accounts with web-friendly API - file system integration included",
    author="Dan Q",
    packages=find_packages(),
    install_requires=[
        "argon2-cffi>=23.1.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "dbaccounts=dbbasic_accounts.cli:main",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)
