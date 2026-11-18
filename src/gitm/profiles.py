"""Exact, pinned recovered eMudhra lab profiles. Never synthesize missing assets."""

import hashlib
import json
from pathlib import Path

from .certificates import CAMaterial, validate_material

PROFILE_ROOT = Path(__file__).resolve().parents[1] / 'profiles/emudhra'
if not PROFILE_ROOT.exists():
    PROFILE_ROOT = Path(__file__).resolve().parents[2] / 'profiles/emudhra'
NAMES = tuple(sorted(f'{v}-g3{k}-{p}' for v in ('dv', 'ov', 'ev') for k in ('b', 'c') for p in ('aaa', 'emsign')))


def list_profiles() -> tuple[str, ...]:
    return NAMES


def _assets(name: str, root: Path) -> dict[str, bytes]:
    if name not in NAMES:
        raise ValueError(f'Unknown eMudhra profile: {name}')
    try:
        pins = json.loads((root / 'provenance.json').read_text())
        required = ['ca.crt', 'ca.key', 'manifest.json', 'trust-anchor.pem']
        if name.endswith('-emsign'):
            required.append('chain.pem')
        values = {}
        for filename in required:
            relative = f'{name}/{filename}'
            path = root / relative
            if path.is_symlink():
                raise ValueError('profile asset symlink rejected')
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() != pins['sha256'][relative]:
                raise ValueError(f'profile provenance mismatch: {relative}')
            values[filename] = data
        return values
    except (OSError, KeyError, json.JSONDecodeError) as exc:
        raise ValueError(f'eMudhra asset-unavailable: {name}; exact corpus required at {root}') from exc


def profile_info(name: str, *, root: Path = PROFILE_ROOT) -> dict:
    values = _assets(name, root)
    return {**json.loads(values['manifest.json']), 'asset_state': 'available',
            'directory': str(root / name), 'chain': str(root / name / 'chain.pem') if 'chain.pem' in values else None}


def verify_profile(name: str, *, root: Path = PROFILE_ROOT) -> CAMaterial:
    values = _assets(name, root)
    # Trust anchor is for offline verification only. SSLsplit gets the parent chain.
    parent_chain = values.get('chain.pem', b'')
    verified = validate_material(values['ca.crt'], values['ca.key'], parent_chain + values['trust-anchor.pem'])
    manifest = json.loads(values['manifest.json'])
    if verified.fingerprint.upper() != manifest['certificate_sha256']:
        raise ValueError('profile certificate fingerprint mismatch')
    return CAMaterial(verified.certificate, verified.private_key, parent_chain, verified.fingerprint, values["trust-anchor.pem"])
