import os
import click
from install_script_analyzer.analyzer.analyzer import check_for_suspicious_patterns


def detect_vulnerabilites(language, file):
    # click.secho(f"Analyzing {language} : {os.path.basename(file)}")

    with open(file,"r") as f:
        script = f.read()
    
    return check_for_suspicious_patterns(script)