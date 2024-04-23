import click
import pyfiglet
from pathlib import Path
from .helper import detect_vulnerabilites
from install_script_analyzer.language_detect.languages import detect_package_language

@click.command()
@click.option('--path', default="./", help='Path to repository to be scanned.',type=click.Path(exists=True,file_okay=False,dir_okay=True))
@click.option('--hide-banner', is_flag=True, help='Hide the banner.')
@click.option('--dev-scan-all', is_flag=True, help='Scan all files in the directory')

def main(path, hide_banner, dev_scan_all):
    if not hide_banner:
        click.secho(pyfiglet.figlet_format("ISA", font = "slant"),fg='bright_blue')

    # For development purposes
    if dev_scan_all:
        file_paths = [str(path) for path in Path(path).rglob('*')]
        count = 0
        for file_path in file_paths:
            try:
                if detect_vulnerabilites('Python', file_path):
                    print(file_path)
                    count += 1
            except:
                print(f"Analysis failed on {file_path}")
        print(f"Count of flagged files = {count}")
        return

    language, file_path = detect_package_language(path)

    if language is None:
        click.secho("Language not detected/supported!", fg='red', bold=True, err=True)
        return 1

    click.secho(f"Language is {language}",fg='green')

    detect_vulnerabilites(language, file_path)

if __name__ == "__main__":
    main()