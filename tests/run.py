#!/usr/bin/env python3
from pathlib import Path
import subprocess
import tempfile

root=Path(__file__).resolve().parent.parent
sources=root/'app/src/main/java/dev/localguard'
with tempfile.TemporaryDirectory(prefix='localguard-tests-') as temporary:
    files=[str(sources/(name+'.java')) for name in ['DomainRules','Dns','Wire','TcpDns']]
    files.append(str(root/'tests/CoreTests.java'))
    subprocess.run(['javac','-encoding','UTF-8','-d',temporary]+files,check=True)
    subprocess.run(['java','-cp',temporary,'dev.localguard.CoreTests'],check=True)
