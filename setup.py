from setuptools import setup, find_packages

with open('README.md') as f:
    README = f.read()

setup(
    name="install-script-analyzer",
    version="0.1.0",
    description="CLi tool to detect malicious code in software package installation scripts",
    long_description=README,
    author="Rajath Reghunath",
    author_email="rr4433@nyu.edu",
    url="https://github.com/rrgodhorus/install-script-analyzer",
    packages=find_packages(exclude=('tests', 'docs')),
    entry_points = {
        'console_scripts': [
            'install-script-analyzer = install_script_analyzer.__main__:main'
        ]
    }
)