import os
import click

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