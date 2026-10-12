#!/usr/bin/env python3
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.request
import zipfile

VERSION = '8.9'
ROOT = Path(__file__).resolve().parent.parent
HOME = Path(os.environ.get('GRADLE_USER_HOME', str(Path.home() / '.gradle')))
CACHE = HOME / 'localguard-bootstrap' / VERSION
DIST = CACHE / ('gradle-' + VERSION)
LAUNCHER = DIST / 'bin' / ('gradle.bat' if os.name == 'nt' else 'gradle')
URL = 'https://services.gradle.org/distributions/gradle-' + VERSION + '-bin.zip'

def main():
    if not LAUNCHER.exists():
        CACHE.mkdir(parents=True, exist_ok=True)
        archive = CACHE / 'distribution.zip'
        partial = CACHE / 'distribution.zip.part'
        print('Descargando Gradle ' + VERSION + ' desde el sitio oficial...')
        with urllib.request.urlopen(URL + '.sha256', timeout=60) as response:
            expected = response.read().decode('ascii').strip().split()[0].lower()
        with urllib.request.urlopen(URL, timeout=120) as response, partial.open('wb') as target:
            shutil.copyfileobj(response, target)
        digest = hashlib.sha256()
        with partial.open('rb') as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b''):
                digest.update(block)
        if digest.hexdigest() != expected:
            partial.unlink(missing_ok=True)
            raise RuntimeError('La suma SHA-256 de Gradle no coincide.')
        partial.replace(archive)
        with zipfile.ZipFile(archive) as bundle:
            for entry in bundle.infolist():
                path = (CACHE / entry.filename).resolve()
                if CACHE.resolve() not in path.parents:
                    raise RuntimeError('Ruta no válida dentro de la distribución.')
            bundle.extractall(CACHE)
        if os.name != 'nt':
            LAUNCHER.chmod(0o755)
        archive.unlink()
    return subprocess.call([str(LAUNCHER)] + sys.argv[1:], cwd=ROOT)

if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print('Error: ' + str(error), file=sys.stderr)
        sys.exit(1)
