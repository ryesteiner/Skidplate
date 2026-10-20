"""Skidplate state naming, with explicit compatibility for existing local history."""
from pathlib import Path


def default_state(state_home):
    state_home = Path(state_home)
    current, legacy = state_home / 'skidplate', state_home / 'audit-sentinel'
    if current.exists() and legacy.exists():
        raise ValueError('Both Skidplate and legacy audit-sentinel state exist; choose explicitly with --state-dir')
    # Store performs private-directory and database ownership/type checks.
    return legacy if legacy.exists() else current


def database_path(directory):
    directory = Path(directory)
    current, legacy = directory / 'skidplate.sqlite3', directory / 'sentinel.sqlite3'
    if current.exists() and legacy.exists():
        raise ValueError('Both current and legacy databases exist; preserve backups and resolve before starting')
    return legacy if legacy.exists() else current
