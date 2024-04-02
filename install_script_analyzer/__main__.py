import click
import pyfiglet
from .helper import detect_package_language, detect_vulnerabilites

@click.command()
@click.option('--path', default="./", help='Path to repository to be scanned.',type=click.Path(exists=True,file_okay=False,dir_okay=True))

def main(path):
    click.secho(pyfiglet.figlet_format("Install Script Analyzer", font = "slant"),fg='bright_blue')

    language, file_path = detect_package_language(path)

    if language is None:
        click.secho("Language not detected/supported!", fg='red', bold=True, err=True)
        return 1
        
    click.secho(f"Language is {language}",fg='green')

    detect_vulnerabilites(language, file_path)

if __name__ == "__main__":
    main()