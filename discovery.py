"""Secret discovery — scan directories for hardcoded secrets.

Phase 9: Scans codebases and config files for patterns that look like
secrets (API keys, tokens, passwords), generates masked reports, and
feeds findings to the auto-vaulter.

No external dependencies — uses stdlib only (os, re, pathlib).
"""

import fnmatch
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("credential-gate.discovery")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class SecretFinding:
    file_path: str
    line_number: int
    pattern_name: str
    matched_value_masked: str   # "ghp_xxxx...xxxx" (first 4 + last 4)
    context_line_masked: str    # full line with secret replaced
    severity: str               # critical, high, medium
    raw_value: str              # actual secret (for vaulting — handle carefully, never log)
    suggested_bw_name: str      # auto-generated Bitwarden item name

    def to_safe_dict(self) -> dict:
        """Serialise WITHOUT raw_value — safe for API responses."""
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "pattern_name": self.pattern_name,
            "matched_value_masked": self.matched_value_masked,
            "context_line_masked": self.context_line_masked,
            "severity": self.severity,
            "suggested_bw_name": self.suggested_bw_name,
        }


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

class SecretScanner:
    """Scan directories for hardcoded secrets."""

    # Built-in patterns (regex-based)
    PATTERNS = [
        # Generic high-entropy strings in assignment context
        {
            "name": "generic_api_key",
            "pattern": r"""(?i)(api[_-]?key|apikey|api[_-]?token)\s*[=:]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?""",
            "severity": "high",
            "group": 2,
        },
        {
            "name": "generic_secret",
            "pattern": r"""(?i)(secret|password|passwd|pwd)\s*[=:]\s*['"]?([^\s'"]{8,})['"]?""",
            "severity": "high",
            "group": 2,
        },
        {
            "name": "generic_token",
            "pattern": r"""(?i)(token|bearer|auth)\s*[=:]\s*['"]?([A-Za-z0-9_\-\.]{20,})['"]?""",
            "severity": "high",
            "group": 2,
        },
        # Service-specific patterns
        {
            "name": "github_pat",
            "pattern": r"""(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})""",
            "severity": "critical",
            "group": 1,
        },
        {
            "name": "github_oauth",
            "pattern": r"""(gho_[A-Za-z0-9]{36})""",
            "severity": "critical",
            "group": 1,
        },
        {
            "name": "slack_token",
            "pattern": r"""(xox[bpors]-[A-Za-z0-9\-]{10,})""",
            "severity": "critical",
            "group": 1,
        },
        {
            "name": "aws_access_key",
            "pattern": r"""(AKIA[0-9A-Z]{16})""",
            "severity": "critical",
            "group": 1,
        },
        {
            "name": "aws_secret_key",
            "pattern": r"""(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?""",
            "severity": "critical",
            "group": 2,
        },
        {
            "name": "private_key",
            "pattern": r"""-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----""",
            "severity": "critical",
            "group": 0,
        },
        {
            "name": "jwt",
            "pattern": r"""eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}""",
            "severity": "high",
            "group": 0,
        },
        {
            "name": "basic_auth_url",
            "pattern": r"""https?://[^:\s]+:([^@\s]+)@""",
            "severity": "high",
            "group": 1,
        },
        {
            "name": "ntfy_topic_in_url",
            "pattern": r"""ntfy\.sh/([a-zA-Z0-9_-]{5,})""",
            "severity": "medium",
            "group": 1,
        },
        {
            "name": "bitwarden_session",
            "pattern": r"""BW_SESSION\s*[=:]\s*['"]?([A-Za-z0-9+/=]{50,})['"]?""",
            "severity": "critical",
            "group": 1,
        },
    ]

    # File extensions to scan
    SCAN_EXTENSIONS = {
        ".py", ".js", ".ts", ".sh", ".bash", ".zsh",
        ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg",
        ".env", ".env.local", ".env.production",
        ".conf", ".config", ".properties",
        ".md",
    }

    # Files with no extension (or special names) to scan
    SCAN_FILENAMES = {
        "Dockerfile", "Makefile", "Vagrantfile",
        ".bashrc", ".zshrc", ".profile", ".bash_profile",
        "config", "credentials", "secrets",
        "TOOLS.md", "CLAUDE.md",
    }

    # Directories to skip
    SKIP_DIRS = {
        ".git", "node_modules", "__pycache__", ".venv", "venv",
        ".mypy_cache", ".pytest_cache", "dist", "build",
        ".tox", ".eggs",
    }

    # Files to skip
    SKIP_FILE_PATTERNS = [
        "package-lock.json", "yarn.lock", "poetry.lock",
        "*.pyc", "*.pyo", "*.so", "*.dylib",
    ]

    # Max file size to scan (1 MB)
    MAX_FILE_SIZE = 1_048_576

    def __init__(self, config: dict):
        self._config = config.get("discovery", {})
        self._custom_patterns = self._config.get("custom_patterns", [])
        self._exclude_paths = self._config.get("exclude_paths", [])
        # Pre-compile all patterns
        self._compiled = []
        for p in self.PATTERNS:
            try:
                self._compiled.append({
                    "name": p["name"],
                    "regex": re.compile(p["pattern"]),
                    "severity": p["severity"],
                    "group": p.get("group", 0),
                    "context_required": p.get("context_required"),
                })
            except re.error as e:
                logger.warning("Failed to compile pattern '%s': %s", p["name"], e)
        # Compile custom patterns
        for cp in self._custom_patterns:
            try:
                self._compiled.append({
                    "name": cp.get("name", "custom"),
                    "regex": re.compile(cp["pattern"]),
                    "severity": cp.get("severity", "medium"),
                    "group": cp.get("group", 0),
                    "context_required": cp.get("context_required"),
                })
            except (re.error, KeyError) as e:
                logger.warning("Failed to compile custom pattern: %s", e)

    def _should_scan_file(self, file_path: Path) -> bool:
        """Decide whether to scan a file."""
        name = file_path.name
        suffix = file_path.suffix

        # Check by name
        if name in self.SCAN_FILENAMES:
            return True

        # Check by extension
        if suffix in self.SCAN_EXTENSIONS:
            return True

        # .env variants (e.g. .env.local, .env.production)
        if name.startswith(".env"):
            return True

        return False

    def _should_skip_dir(self, dir_name: str) -> bool:
        """Check if a directory should be skipped."""
        if dir_name in self.SKIP_DIRS:
            return True
        # egg-info dirs
        if dir_name.endswith(".egg-info"):
            return True
        return False

    def _should_skip_file(self, file_name: str) -> bool:
        """Check if a specific file should be skipped."""
        for pattern in self.SKIP_FILE_PATTERNS:
            if fnmatch.fnmatch(file_name, pattern):
                return True
        return False

    def _is_excluded_path(self, file_path: str) -> bool:
        """Check if a path matches any exclusion pattern."""
        for pattern in self._exclude_paths:
            if fnmatch.fnmatch(file_path, pattern):
                return True
        return False

    def _is_binary(self, file_path: Path) -> bool:
        """Quick binary check — look for null bytes in first 512 bytes."""
        try:
            with open(file_path, "rb") as f:
                chunk = f.read(512)
                return b"\x00" in chunk
        except (OSError, IOError):
            return True

    @staticmethod
    def _mask_value(value: str) -> str:
        """Mask a secret value: show first 4 + last 4 chars."""
        if len(value) <= 8:
            return value[:2] + "****" + value[-2:] if len(value) >= 4 else "****"
        return value[:4] + "..." + value[-4:]

    @staticmethod
    def _mask_line(line: str, secret: str) -> str:
        """Replace the secret in the context line with a masked version."""
        if not secret:
            return line
        masked = SecretScanner._mask_value(secret)
        return line.replace(secret, masked)

    @staticmethod
    def _suggest_bw_name(pattern_name: str, file_path: str) -> str:
        """Generate a suggested Bitwarden item name from the finding."""
        file_stem = Path(file_path).stem
        # Clean up the stem
        clean_stem = re.sub(r"[^a-zA-Z0-9_-]", "-", file_stem).strip("-")
        return f"{pattern_name}-from-{clean_stem}"

    def scan_file(self, file_path: str) -> list[SecretFinding]:
        """Scan a single file for secrets."""
        path = Path(file_path)
        findings: list[SecretFinding] = []

        if not path.is_file():
            return findings

        # Size check
        try:
            if path.stat().st_size > self.MAX_FILE_SIZE:
                return findings
        except OSError:
            return findings

        # Binary check
        if self._is_binary(path):
            return findings

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line_number, line in enumerate(f, start=1):
                    line_stripped = line.rstrip("\n\r")
                    for pat in self._compiled:
                        # Context check — some patterns need surrounding context
                        if pat["context_required"]:
                            if pat["context_required"].lower() not in line_stripped.lower():
                                continue

                        match = pat["regex"].search(line_stripped)
                        if not match:
                            continue

                        # Extract the matched secret value
                        try:
                            raw_value = match.group(pat["group"])
                        except (IndexError, AttributeError):
                            raw_value = match.group(0)

                        if not raw_value or len(raw_value) < 4:
                            continue

                        findings.append(SecretFinding(
                            file_path=str(path),
                            line_number=line_number,
                            pattern_name=pat["name"],
                            matched_value_masked=self._mask_value(raw_value),
                            context_line_masked=self._mask_line(line_stripped, raw_value),
                            severity=pat["severity"],
                            raw_value=raw_value,
                            suggested_bw_name=self._suggest_bw_name(pat["name"], str(path)),
                        ))
        except (OSError, UnicodeDecodeError) as e:
            logger.debug("Could not scan %s: %s", file_path, e)

        return findings

    def scan_directory(
        self,
        path: str,
        recursive: bool = True,
        severity_filter: str = "medium",
    ) -> tuple[list[SecretFinding], int]:
        """Scan a directory for hardcoded secrets.

        Returns (findings, files_scanned_count).
        """
        severity_order = {"critical": 3, "high": 2, "medium": 1}
        min_severity = severity_order.get(severity_filter, 1)

        root = Path(path)
        if not root.is_dir():
            logger.warning("Scan path is not a directory: %s", path)
            return [], 0

        all_findings: list[SecretFinding] = []
        files_scanned = 0

        if recursive:
            for dirpath, dirnames, filenames in os.walk(root):
                # Filter out skip dirs in-place (prevents os.walk from descending)
                dirnames[:] = [
                    d for d in dirnames
                    if not self._should_skip_dir(d)
                ]

                for fname in filenames:
                    full_path = os.path.join(dirpath, fname)

                    if self._should_skip_file(fname):
                        continue

                    if self._is_excluded_path(full_path):
                        continue

                    fp = Path(full_path)
                    if not self._should_scan_file(fp):
                        continue

                    files_scanned += 1
                    file_findings = self.scan_file(full_path)
                    # Apply severity filter
                    for f in file_findings:
                        if severity_order.get(f.severity, 0) >= min_severity:
                            all_findings.append(f)
        else:
            # Non-recursive — scan only direct children
            try:
                for entry in os.scandir(root):
                    if not entry.is_file():
                        continue
                    if self._should_skip_file(entry.name):
                        continue
                    if self._is_excluded_path(entry.path):
                        continue
                    fp = Path(entry.path)
                    if not self._should_scan_file(fp):
                        continue

                    files_scanned += 1
                    file_findings = self.scan_file(entry.path)
                    for f in file_findings:
                        if severity_order.get(f.severity, 0) >= min_severity:
                            all_findings.append(f)
            except OSError as e:
                logger.warning("Could not scan directory %s: %s", path, e)

        return all_findings, files_scanned

    def generate_report(self, findings: list[SecretFinding], scan_path: str, files_scanned: int) -> dict:
        """Aggregate findings into a report."""
        files_with_secrets = len({f.file_path for f in findings})

        by_severity: dict[str, int] = {}
        by_pattern: dict[str, int] = {}
        for f in findings:
            by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
            by_pattern[f.pattern_name] = by_pattern.get(f.pattern_name, 0) + 1

        return {
            "scan_path": scan_path,
            "files_scanned": files_scanned,
            "files_with_secrets": files_with_secrets,
            "total_findings": len(findings),
            "by_severity": by_severity,
            "by_pattern": by_pattern,
            "findings": [f.to_safe_dict() for f in findings],
        }
