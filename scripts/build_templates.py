#!/usr/bin/env python3
"""Generate templates.json from Surge/ and Stash/ directories.
Usage: python3 build_templates.py > templates.json"""

import json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RAW_BASE = "https://raw.githubusercontent.com/0xMario27/Stencil/main"

manifest = {}

# Surge templates (*.conf)
surge_dir = ROOT / "Surge"
surge_tpls = sorted(f.name for f in surge_dir.glob("*.conf") if not f.name.startswith(".") and "filled" not in f.name)
if surge_tpls:
    manifest["Surge"] = {t: f"{RAW_BASE}/Surge/{t}" for t in surge_tpls}

# Stash templates (*.yaml)
stash_dir = ROOT / "Stash"
stash_tpls = sorted(f.name for f in stash_dir.glob("*.yaml") if not f.name.startswith(".") and "filled" not in f.name)
if stash_tpls:
    manifest["Stash"] = {t: f"{RAW_BASE}/Stash/{t}" for t in stash_tpls}

json.dump(manifest, sys.stdout, indent=2)
print()
