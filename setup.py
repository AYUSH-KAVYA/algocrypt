from setuptools import setup, find_packages

setup(
    name="algocrypt",
    version="1.0.0",
    description="AI/ML Cryptographic Algorithm Identification CLI Tool",
    author="AYUSH-KAVYA",
    packages=find_packages(),
    py_modules=[],
    install_requires=[
        "click>=8.1.0",
        "pycryptodome>=3.20.0",
        "scikit-learn>=1.4.0",
        "pandas>=2.0.0",
        "numpy>=1.26.0",
        "joblib>=1.3.0",
    ],
    entry_points={
        "console_scripts": [
            "algocrypt=src.cli:main",
        ],
    },
    python_requires=">=3.8",
)
