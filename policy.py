"""Policy engine for Credential Gate.

Loads YAML policy files from the policies/ directory and evaluates them
at request time.  Each agent gets a policy file controlling what they can
access, when, how often, and at what approval level.

Policies are hot-reloadable — file mtime is checked on every request and
the policy is re-parsed when the file changes.

Phase 4 implementation.
"""

import calendar
import json
import logging
import time
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml

logger = logging.getLogger(__name__)

# Valid values for approval mode and risk levels
VALID_APPROVAL_MODES = {"yubikey", "phone", "both"}
VALID_RISK_LEVELS = {"low", "medium", "high", "critical"}
VALID_ON_EXCEED = {"deny", "deny_and_alert", "queue"}


class LeasePolicy:
    """Lease-specific policy settings for a credential."""

    __slots__ = (
        "lease_ttl_minutes",
        "max_lease_minutes",
        "max_concurrent_leases",
        "rotate_on_expire",
    )

    def __init__(
        self,
        lease_ttl_minutes: int = 15,
        max_lease_minutes: int = 60,
        max_concurrent_leases: int = 10,
        rotate_on_expire: bool = False,
    ):
        self.lease_ttl_minutes = lease_ttl_minutes
        self.max_lease_minutes = max_lease_minutes
        self.max_concurrent_leases = max_concurrent_leases
        self.rotate_on_expire = rotate_on_expire

    @property
    def ttl_seconds(self) -> int:
        return self.lease_ttl_minutes * 60

    @property
    def max_lease_seconds(self) -> int:
        return self.max_lease_minutes * 60

    def to_dict(self) -> dict:
        return {
            "lease_ttl_minutes": self.lease_ttl_minutes,
            "max_lease_minutes": self.max_lease_minutes,
            "max_concurrent_leases": self.max_concurrent_leases,
            "rotate_on_expire": self.rotate_on_expire,
        }


# Default lease policy when none is specified
_DEFAULT_LEASE_POLICY = LeasePolicy()


class PolicyDecision:
    """Result of policy evaluation for a single credential request."""

    def __init__(
        self,
        allowed: bool,
        reason: str = "",
        approval_mode: str = "both",
        auto_approve_seconds: int | None = None,
        alert_always: bool = False,
        checks: list[dict] | None = None,
        lease_policy: LeasePolicy | None = None,
    ):
        self.allowed = allowed
        self.reason = reason
        self.approval_mode = approval_mode
        self.auto_approve_seconds = auto_approve_seconds
        self.alert_always = alert_always
        self.checks = checks or []
        self.lease_policy = lease_policy or _DEFAULT_LEASE_POLICY

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "approval_mode": self.approval_mode,
            "auto_approve_seconds": self.auto_approve_seconds,
            "alert_always": self.alert_always,
            "checks": self.checks,
            "lease_policy": self.lease_policy.to_dict(),
        }


class AgentPolicy:
    """Loaded policy for a single agent."""

    def __init__(self, agent_id: str, policy_dict: dict):
        self.agent_id = agent_id
        self.default_approval = policy_dict.get("default_approval", "both")
        self.schedule = policy_dict.get("schedule", {})
        self.rate_limits = policy_dict.get("rate_limits", {})
        self.credentials = policy_dict.get("credentials", {})

    def get_credential_policy(self, credential_name: str) -> dict:
        """Return the most specific policy for this credential."""
        if credential_name in self.credentials:
            return self.credentials[credential_name]
        return self.credentials.get("*", {
            "risk": "medium",
            "approval": self.default_approval,
        })

    def get_lease_policy(self, credential_name: str) -> LeasePolicy:
        """Build a LeasePolicy from the credential-specific and wildcard settings."""
        # Start with wildcard defaults
        wildcard = self.credentials.get("*", {})
        specific = self.credentials.get(credential_name, {})

        # Merge: specific overrides wildcard
        def _get(key, default):
            if key in specific:
                return specific[key]
            if key in wildcard:
                return wildcard[key]
            return default

        return LeasePolicy(
            lease_ttl_minutes=_get("lease_ttl_minutes", 15),
            max_lease_minutes=_get("max_lease_minutes", 60),
            max_concurrent_leases=_get("max_concurrent_leases", 10),
            rotate_on_expire=_get("rotate_on_expire", False),
        )

    def check_schedule(self) -> tuple[bool, str]:
        """Check if current time is within allowed hours.

        Returns (allowed, reason).
        """
        if not self.schedule or not self.schedule.get("allowed_hours"):
            return True, ""

        tz_name = self.schedule.get("timezone", "UTC")
        try:
            tz = ZoneInfo(tz_name)
        except (KeyError, Exception):
            logger.warning("Invalid timezone '%s' in policy, allowing", tz_name)
            return True, ""

        now = datetime.now(tz)
        allowed_hours = self.schedule["allowed_hours"]

        try:
            start_str, end_str = allowed_hours.split("-")
            start_h, start_m = map(int, start_str.strip().split(":"))
            end_h, end_m = map(int, end_str.strip().split(":"))
        except (ValueError, AttributeError):
            logger.warning("Invalid allowed_hours format '%s', allowing", allowed_hours)
            return True, ""

        current_minutes = now.hour * 60 + now.minute
        start_minutes = start_h * 60 + start_m
        end_minutes = end_h * 60 + end_m

        if start_minutes <= current_minutes < end_minutes:
            return True, ""

        return False, (
            f"Outside allowed schedule ({allowed_hours} {tz_name})"
        )

    def check_rate_limit(self, audit_log) -> tuple[bool, str]:
        """Query audit DB for recent request counts.

        Returns (allowed, reason).
        """
        if not self.rate_limits:
            return True, ""

        conn = audit_log._conn
        now_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        checks = [
            ("per_minute", 60),
            ("per_hour", 3600),
            ("per_day", 86400),
        ]

        for limit_key, seconds in checks:
            limit_val = self.rate_limits.get(limit_key)
            if limit_val is None:
                continue

            cutoff = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(time.time() - seconds),
            )

            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM audit_log "
                "WHERE agent_id = ? AND timestamp >= ? AND status = 'approved'",
                (self.agent_id, cutoff),
            ).fetchone()

            count = row[0] if row else 0
            if count >= limit_val:
                window = limit_key.replace("per_", "")
                return False, f"Rate limit exceeded ({limit_val}/{window})"

        return True, ""

    def check_cooldown(self, credential_name: str, audit_log) -> tuple[bool, str]:
        """Check if credential was requested too recently.

        Returns (allowed, reason).
        """
        cred_policy = self.get_credential_policy(credential_name)
        cooldown_minutes = cred_policy.get("cooldown_minutes", 0)
        if not cooldown_minutes:
            return True, ""

        cutoff = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(time.time() - cooldown_minutes * 60),
        )

        conn = audit_log._conn
        row = conn.execute(
            "SELECT timestamp FROM audit_log "
            "WHERE agent_id = ? AND credential_name = ? "
            "AND status = 'approved' AND timestamp >= ? "
            "ORDER BY id DESC LIMIT 1",
            (self.agent_id, credential_name, cutoff),
        ).fetchone()

        if row:
            # Calculate remaining cooldown
            last_ts = row[0]
            try:
                last_time = calendar.timegm(time.strptime(last_ts, "%Y-%m-%dT%H:%M:%SZ"))
                elapsed = time.time() - last_time
                remaining = int((cooldown_minutes * 60 - elapsed) / 60)
                if remaining < 1:
                    remaining = 1
            except (ValueError, OverflowError):
                remaining = cooldown_minutes
            return False, f"Cooldown active ({remaining} min remaining)"

        return True, ""

    def check_prerequisites(self, credential_name: str, audit_log) -> tuple[bool, str]:
        """Check if required credentials were requested first.

        Returns (allowed, reason).
        """
        cred_policy = self.get_credential_policy(credential_name)
        requires = cred_policy.get("requires", [])
        if not requires:
            return True, ""

        conn = audit_log._conn

        for prereq in requires:
            row = conn.execute(
                "SELECT id FROM audit_log "
                "WHERE agent_id = ? AND credential_name = ? "
                "AND status = 'approved' "
                "ORDER BY id DESC LIMIT 1",
                (self.agent_id, prereq),
            ).fetchone()

            if not row:
                return False, f"Prerequisite not met: must request '{prereq}' first"

        return True, ""

    def evaluate(self, credential_name: str, audit_log) -> PolicyDecision:
        """Run all policy checks. Returns a PolicyDecision."""
        checks = []
        cred_policy = self.get_credential_policy(credential_name)

        # 1. Schedule check
        allowed, reason = self.check_schedule()
        checks.append({"check": "schedule", "allowed": allowed, "reason": reason})
        if not allowed:
            override_approval = self.schedule.get("override_approval")
            if override_approval:
                # Allow with overridden approval mode
                checks[-1]["allowed"] = True
                checks[-1]["reason"] = f"Outside schedule, override to {override_approval}"
                # Continue evaluation with overridden mode
                effective_approval = override_approval
            else:
                return PolicyDecision(
                    allowed=False,
                    reason=reason,
                    checks=checks,
                )
        else:
            effective_approval = cred_policy.get("approval", self.default_approval)

        # If schedule was in-hours, use credential-level approval
        if allowed:
            effective_approval = cred_policy.get("approval", self.default_approval)

        # 2. Rate limit check
        rl_allowed, rl_reason = self.check_rate_limit(audit_log)
        checks.append({"check": "rate_limit", "allowed": rl_allowed, "reason": rl_reason})
        if not rl_allowed:
            on_exceed = self.rate_limits.get("on_exceed", "deny")
            if on_exceed == "deny_and_alert":
                return PolicyDecision(
                    allowed=False,
                    reason=rl_reason,
                    alert_always=True,
                    checks=checks,
                )
            elif on_exceed == "deny" or on_exceed == "queue":
                return PolicyDecision(
                    allowed=False,
                    reason=rl_reason,
                    checks=checks,
                )

        # 3. Cooldown check
        cd_allowed, cd_reason = self.check_cooldown(credential_name, audit_log)
        checks.append({"check": "cooldown", "allowed": cd_allowed, "reason": cd_reason})
        if not cd_allowed:
            return PolicyDecision(
                allowed=False,
                reason=cd_reason,
                checks=checks,
            )

        # 4. Prerequisites check
        pr_allowed, pr_reason = self.check_prerequisites(credential_name, audit_log)
        checks.append({"check": "prerequisites", "allowed": pr_allowed, "reason": pr_reason})
        if not pr_allowed:
            return PolicyDecision(
                allowed=False,
                reason=pr_reason,
                checks=checks,
            )

        # All checks passed
        lease_policy = self.get_lease_policy(credential_name)
        return PolicyDecision(
            allowed=True,
            approval_mode=effective_approval,
            auto_approve_seconds=cred_policy.get("auto_approve_seconds"),
            alert_always=cred_policy.get("alert_always", False),
            checks=checks,
            lease_policy=lease_policy,
        )


# ---------------------------------------------------------------------------
# Policy loader with hot-reload (checks file mtime)
# ---------------------------------------------------------------------------

class _CachedPolicy:
    """Wrapper holding a parsed policy and the mtime at load time."""
    __slots__ = ("policy", "mtime")

    def __init__(self, policy: AgentPolicy, mtime: float):
        self.policy = policy
        self.mtime = mtime


_cache: dict[str, _CachedPolicy] = {}


def _policy_path(policies_dir: str, agent_id: str) -> Path:
    return Path(policies_dir) / f"{agent_id}.yaml"


def load_agent_policy(policies_dir: str, agent_id: str) -> AgentPolicy | None:
    """Load and cache an agent's policy file, hot-reloading on mtime change.

    Returns None if the policy file does not exist.
    """
    path = _policy_path(policies_dir, agent_id)

    if not path.exists():
        # Remove stale cache entry if the file was deleted
        _cache.pop(agent_id, None)
        return None

    try:
        current_mtime = path.stat().st_mtime
    except OSError:
        return None

    cached = _cache.get(agent_id)
    if cached and cached.mtime == current_mtime:
        return cached.policy

    # (Re)load
    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    except Exception as e:
        logger.error("Failed to parse policy file %s: %s", path, e)
        return None

    policy = AgentPolicy(agent_id, data)
    _cache[agent_id] = _CachedPolicy(policy, current_mtime)

    logger.info("Loaded policy for agent '%s' from %s", agent_id, path)
    return policy


def validate_policy_file(path: Path) -> list[str]:
    """Validate a policy YAML file. Returns a list of error strings (empty = valid)."""
    errors = []

    try:
        with open(path) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return [f"YAML syntax error: {e}"]
    except Exception as e:
        return [f"Cannot read file: {e}"]

    if not isinstance(data, dict):
        return ["Policy file must be a YAML mapping"]

    # Check default_approval
    default_approval = data.get("default_approval", "both")
    if default_approval not in VALID_APPROVAL_MODES:
        errors.append(f"Invalid default_approval '{default_approval}' (must be one of {VALID_APPROVAL_MODES})")

    # Check schedule
    schedule = data.get("schedule", {})
    if schedule:
        allowed_hours = schedule.get("allowed_hours", "")
        if allowed_hours:
            try:
                start_str, end_str = allowed_hours.split("-")
                int(start_str.strip().split(":")[0])
                int(start_str.strip().split(":")[1])
                int(end_str.strip().split(":")[0])
                int(end_str.strip().split(":")[1])
            except (ValueError, AttributeError):
                errors.append(f"Invalid allowed_hours format '{allowed_hours}' (expected 'HH:MM-HH:MM')")

        override = schedule.get("override_approval")
        if override and override not in VALID_APPROVAL_MODES:
            errors.append(f"Invalid override_approval '{override}' (must be one of {VALID_APPROVAL_MODES})")

        tz = schedule.get("timezone")
        if tz:
            try:
                ZoneInfo(tz)
            except (KeyError, Exception):
                errors.append(f"Invalid timezone '{tz}'")

    # Check rate_limits
    rate_limits = data.get("rate_limits", {})
    if rate_limits:
        for key in ("per_minute", "per_hour", "per_day"):
            val = rate_limits.get(key)
            if val is not None and (not isinstance(val, int) or val < 1):
                errors.append(f"rate_limits.{key} must be a positive integer, got {val!r}")

        on_exceed = rate_limits.get("on_exceed", "deny")
        if on_exceed not in VALID_ON_EXCEED:
            errors.append(f"Invalid on_exceed '{on_exceed}' (must be one of {VALID_ON_EXCEED})")

    # Check credentials
    credentials = data.get("credentials", {})
    if credentials:
        for cred_name, cred_cfg in credentials.items():
            if not isinstance(cred_cfg, dict):
                errors.append(f"Credential '{cred_name}' must be a mapping")
                continue

            risk = cred_cfg.get("risk")
            if risk and risk not in VALID_RISK_LEVELS:
                errors.append(f"Credential '{cred_name}': invalid risk '{risk}' (must be one of {VALID_RISK_LEVELS})")

            approval = cred_cfg.get("approval")
            if approval and approval not in VALID_APPROVAL_MODES:
                errors.append(f"Credential '{cred_name}': invalid approval '{approval}' (must be one of {VALID_APPROVAL_MODES})")

            cooldown = cred_cfg.get("cooldown_minutes")
            if cooldown is not None and (not isinstance(cooldown, (int, float)) or cooldown < 0):
                errors.append(f"Credential '{cred_name}': cooldown_minutes must be >= 0")

            auto_approve = cred_cfg.get("auto_approve_seconds")
            if auto_approve is not None and (not isinstance(auto_approve, (int, float)) or auto_approve < 1):
                errors.append(f"Credential '{cred_name}': auto_approve_seconds must be >= 1")

            requires = cred_cfg.get("requires")
            if requires is not None and not isinstance(requires, list):
                errors.append(f"Credential '{cred_name}': requires must be a list")

            # Lease fields
            lease_ttl = cred_cfg.get("lease_ttl_minutes")
            if lease_ttl is not None and (not isinstance(lease_ttl, (int, float)) or lease_ttl < 1):
                errors.append(f"Credential '{cred_name}': lease_ttl_minutes must be >= 1")

            max_lease = cred_cfg.get("max_lease_minutes")
            if max_lease is not None and (not isinstance(max_lease, (int, float)) or max_lease < 1):
                errors.append(f"Credential '{cred_name}': max_lease_minutes must be >= 1")

            max_concurrent = cred_cfg.get("max_concurrent_leases")
            if max_concurrent is not None and (not isinstance(max_concurrent, int) or max_concurrent < 1):
                errors.append(f"Credential '{cred_name}': max_concurrent_leases must be >= 1")

            rotate_on_expire = cred_cfg.get("rotate_on_expire")
            if rotate_on_expire is not None and not isinstance(rotate_on_expire, bool):
                errors.append(f"Credential '{cred_name}': rotate_on_expire must be a boolean")

    return errors
