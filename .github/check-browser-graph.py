#!/usr/bin/env python3
"""Confirm browser tests execute this facade and its original portable owner."""
import json
import re
from pathlib import Path

metadata = json.loads(Path('browser-dependency-metadata.json').read_text())
facades = [p for p in metadata['packages'] if p['name'] == 'cfyr']
owners = [p for p in metadata['packages'] if p['name'] == 'cvld']
if len(facades) != 1 or len(owners) != 1:
    raise SystemExit('Expected exactly one Foyer and one door owner')
facade, owner = facades[0], owners[0]
if facade['source'] is not None or Path(facade['manifest_path']).resolve() != Path('Cargo.toml').resolve():
    raise SystemExit('Browser test must execute this local Foyer source')
# The lock names the door owner by its canonical forge path (corbet-libs -> corbet-fsl on 2026-11-09) and
# carries the `.git` suffix; accept both spellings so a lock refreshed before or after the move passes.
if not re.fullmatch(r'git\+https://git\.corbet\.ch/corbet-fsl/cvld(?:\.git)?\?branch=main#[0-9a-f]{40}', owner['source'] or ''):
    raise SystemExit('Browser test must use the original door main graph')
nodes = {node['id']: set(node['features']) for node in metadata['resolve']['nodes']}
if 'browser' not in nodes[facade['id']] or 'http' in nodes[facade['id']]:
    raise SystemExit('Expected the actual browser facade')
features = nodes[owner['id']]
if 'client-browser' not in features or features & {'server', 'development-gate', 'client-http'}:
    raise SystemExit('Browser consumer must use the actual portable door adapter')
print('Browser consumer executes this Foyer and the original portable door')

for name, feature in [('cnvy', 'browser')]:
    packages = [p for p in metadata['packages'] if p['name'] == name]
    # The nightly lock refresh moved the owner source to its canonical forge path (corbet-foss -> corbet-libre
    # on 2026-11-09) and to main; accept the pre-refresh spelling too so either lock passes.
    if len(packages) != 1 or not re.fullmatch(r'git\+https://git\.corbet\.ch/corbet-libre/' + name + r'(?:\.git)?\?branch=(?:v01|main)#[0-9a-f]{40}', packages[0]['source'] or ''):
        raise SystemExit('Browser trust must use exactly one original owner source')
    enabled = nodes[packages[0]['id']]
    if feature not in enabled or 'http' in enabled:
        raise SystemExit('Expected the original browser trust transport only')
