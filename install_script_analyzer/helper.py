import os
import click
import ast
import re

# TODO: Make this more general, using a library perhaps
# Currently supports Python only
def detect_package_language(path):

    click.secho(f"Scanning {path}...")

    if not os.path.exists(os.path.abspath(path).replace("~","")):
        click.secho("Path does not exist",fg='red', err=True)
    
    setup_path = os.path.join(path,"setup.py")
    if os.path.exists(setup_path):
        click.secho('Found setup.py...', fg='green')
        return 'Python',setup_path
    
    return None

suspicious_import_modules = ["ctypes", "win32com", "socket","getpass","tempfile","base64"]
suspicious_import_aliases = ["NamedTemporaryFile"]
suspicious_function_calls = ["exec"]

class NodeVisitor(ast.NodeVisitor):

    def __init__(self):
        self.vulnerabilites = []

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module in suspicious_import_modules:
            self.vulnerabilites.append(f"Potentially Malicious Import: '{node.module}' on line {node.lineno}")
        for alias in node.names:
            if alias.name in suspicious_import_aliases:
                self.vulnerabilites.append(f"Potentially Malicious Import: '{alias.name}' on line {alias.lineno}")
        self.generic_visit(node)
    
    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name in suspicious_import_modules:
                self.vulnerabilites.append(f"Potentially Malicious Import: '{alias.name}' on line {alias.lineno}")
        self.generic_visit(node)
    
    def visit_Name(self, node: ast.Name):
        if node.id in suspicious_function_calls:
            self.vulnerabilites.append(f"Potentially Malicious Function call '{node.id}' on line {node.lineno}")


def detect_vulnerabilites(language, file):
    click.secho(f"Analyzing {language} : {os.path.basename(file)}")

    with open(file,"r") as f:
        script = f.read()
    
    node = ast.parse(script)
    check_for_suspicious_imports(node)
    

def check_for_suspicious_imports(node: ast.AST):
    
    visitor = NodeVisitor()
    visitor.visit(node)
    vulnerabilites = visitor.vulnerabilites
    for vulnerability in vulnerabilites:
        click.secho(vulnerability,fg="yellow",bg='red')
