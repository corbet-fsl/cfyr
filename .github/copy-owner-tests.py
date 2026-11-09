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
# The lock names the door owner by its canonical forge path (corbet-libs -> corbet-fsl on 2026-11-09) and
# carries the `.git` suffix; accept both spellings so a lock refreshed before or after the move passes.
if not re.fullmatch(r'git\+https://git\.corbet\.ch/corbet-(?:libs|fsl)/cvld(?:\.git)?\?branch=main#[0-9a-f]{40}', owner['source']):
    raise SystemExit('Expected a resolved main revision of the door owner')
source = Path(owner['manifest_path']).parent.resolve()
destination = Path('tests/owner')
destination.mkdir(parents=True, exist_ok=True)
# Copy every module the owner's support fixture declares, so new owner modules follow automatically.
names = sorted(path.name for path in (source / 'tests/support').glob('*.rs'))
if 'mod.rs' not in names:
    raise SystemExit('Owner fixture has no tests/support/mod.rs')
for name in names:
    fixture = (source / 'tests/support' / name).resolve()
    if not fixture.is_relative_to(source):
        raise SystemExit('Owner fixture escapes its source directory')
    shutil.copyfile(fixture, destination / name)
Path('owner-fixture.json').write_text(json.dumps({'source': owner['source'], 'files': ['tests/support/' + name for name in names]}, indent=2) + '\n')
