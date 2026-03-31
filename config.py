"""Configuration loader for Credential Gate."""

import os
from pathlib import Path

import yaml


_BASE_DIR = Path(__file__).resolve().parent


def _resolve_path(raw: str | None, default: str) -> Path:
    """Resolve a path relative to the project root."""
    p = Path(raw or default)
    if not p.is_absolute():
        p = _BASE_DIR / p
    return p


def load_config(path: str | Path | None = None) -> dict:
    """Load config.yaml and return the parsed dict.

    Paths inside the config (db_path, credential_store, cli_path) are
    resolved relative to the project root directory.
    """
    if path is None:
        path = _BASE_DIR / "config.yaml"
    path = Path(path)

    with open(path) as f:
        cfg = yaml.safe_load(f)

    # Resolve relative paths
    cfg.setdefault("audit", {})
    cfg["audit"]["db_path"] = str(
        _resolve_path(cfg["audit"].get("db_path"), "data/audit.db")
    )

    cfg.setdefault("fido2", {})
    cfg["fido2"]["credential_store"] = str(
        _resolve_path(cfg["fido2"].get("credential_store"), "data/fido2_credentials.json")
    )

    bw = cfg.setdefault("bitwarden", {})
    if bw.get("cli_path"):
        bw["cli_path"] = str(_resolve_path(bw["cli_path"], "bw"))

    return cfg
