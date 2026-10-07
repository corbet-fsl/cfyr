#!/usr/bin/env python3
"""Reuse the real test server from the exact resolved cvld source."""
import json
import re
import shutil
from pathlib import Path

metadata = json.loads(Path('dependency-metadata.json').read_text())
owners = [package for package in metadata['packages'] if package['name'] == 'cvld']
if len(owners) != 1:
    raise SystemExit('Expected exactly one resolved door owner')
owner = owners[0]
if not re.fullmatch(r'git\+https://git\.corbet\.ch/corbet-libs/cvld\?branch=main#[0-9a-f]{40}', owner['source']):
    raise SystemExit('Expected a resolved main revision of the door owner')
source = Path(owner['manifest_path']).parent.resolve()
destination = Path('tests/owner')
destination.mkdir(parents=True, exist_ok=True)
names = ['mod.rs', 'resident.rs']
if (source / 'tests/support/client_faults.rs').is_file():
    names.append('client_faults.rs')
for name in names:
    fixture = (source / 'tests/support' / name).resolve()
    if not fixture.is_relative_to(source):
        raise SystemExit('Owner fixture escapes its source directory')
    shutil.copyfile(fixture, destination / name)
Path('owner-fixture.json').write_text(json.dumps({'source': owner['source'], 'files': ['tests/support/' + name for name in names]}, indent=2) + '\n')
