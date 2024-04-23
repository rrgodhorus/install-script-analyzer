import click
import ast
import re

suspicious_import_modules = ["ctypes", "win32com", "socket", "getpass", "base64", "requests", "urllib"]
suspicious_import_aliases = ["NamedTemporaryFile", "executable"]
# suspicious_function_calls = []
suspicious_function_calls = ["exec", "eval"]

class NodeVisitor(ast.NodeVisitor):

    def __init__(self):
        self.vulnerabilites = []

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module.split(".")[0] in suspicious_import_modules:
            self.vulnerabilites.append(f"Potentially Malicious Import: '{node.module}' on line {node.lineno}")
        for alias in node.names:
            if alias.name in suspicious_import_aliases:
                self.vulnerabilites.append(f"Potentially Malicious Import: '{alias.name}' on line {alias.lineno}")
        self.generic_visit(node)
    
    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            if alias.name.split(".")[0] in suspicious_import_modules:
                self.vulnerabilites.append(f"Potentially Malicious Import: '{alias.name}' on line {alias.lineno}")
        self.generic_visit(node)
    
    def visit_Name(self, node: ast.Name):
        if node.id in suspicious_function_calls:
            self.vulnerabilites.append(f"Potentially Malicious Function call '{node.id}' on line {node.lineno}")
        self.generic_visit(node)
    
    def visit_Constant(self, node: ast.Constant):
        try:
            # Plain IP addresses
            if isinstance(node.value, str):
                ip_addresses = re.findall(r'(?<!\=)\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b', node.value)
                if ip_addresses:
                    self.vulnerabilites.append(f"Plain IP addresses {ip_addresses} found on line {node.lineno}")
            # print(type(node.value))
            parsed_string_ast = ast.parse(node.value)
            visitor = NodeVisitor()
            visitor.visit(parsed_string_ast)
            if visitor.vulnerabilites:
                self.vulnerabilites.append(f"Obfuscated code found on line {node.lineno}")
        except Exception as e:
            pass
        finally:
            self.generic_visit(node)

def check_for_suspicious_patterns(script):
    
    try:
        node = ast.parse(script)
    except Exception as e:
        click.secho(f"AST parse failed on {file}", fg='red', err=True)
        print(e)
        return 
    visitor = NodeVisitor()
    visitor.visit(node)
    vulnerabilites = visitor.vulnerabilites
    for vulnerability in vulnerabilites:
        click.secho(vulnerability,fg="yellow",bg='red')
    return True if vulnerabilites else False
