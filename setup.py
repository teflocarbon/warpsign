from setuptools import setup, find_packages

setup(
    name="warpsign",
    version="0.1.0",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "rich",
        "requests",
        "python-dotenv",
        "srp",
        "lief",
        "pillow",
        "toml",
        "rich-argparse",
    ],
    entry_points={
        "console_scripts": [
            "warpsign=warpsign.cli:main",
        ],
    },
)
