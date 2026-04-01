#!/usr/bin/env python3
"""Credential Gate — setup and administration.

Usage:
    python setup.py register         Register a YubiKey for FIDO2 assertion
    python setup.py gen-key          Generate an API key for an agent
    python setup.py check            Verify device, config, and service status
    python setup.py store-password   Store Bitwarden master password in Keychain
    python setup.py test-ntfy        Send a test notification via Ntfy
    python setup.py test-phone       Test phone approval flow end-to-end
"""

import getpass
import secrets
import sys

from config import load_config


def cmd_register():
    """Register a YubiKey with the Credential Gate service."""
    from fido import FIDO2_AVAILABLE

    cfg = load_config()

    # Phase 12: Check tier before registration
    tier = cfg.get("security_tier", "gold")
    if tier == "silver":
        print("Security tier is 'silver' (phone-only mode).")
        print("YubiKey registration is not needed for silver tier.")
        print("If you want to use a YubiKey, set security_tier: gold in config.yaml.")
        sys.exit(0)

    if not FIDO2_AVAILABLE:
        print("ERROR: python-fido2 is not installed.")
        print("Install it: pip install fido2")
        print("Or use silver tier (phone-only): set security_tier: silver in config.yaml.")
        sys.exit(1)

    from fido import register, list_devices
    fido2_cfg = cfg.get("fido2", {})

    print("Credential Gate — YubiKey Registration")
    print("=" * 40)

    # Check for connected devices
    devices = list_devices()
    if not devices:
        print("\nERROR: No FIDO2 device found.")
        print("Make sure your YubiKey is plugged into a USB port.")
        sys.exit(1)

    dev = devices[0]
    print(f"\nFound device: {dev.descriptor.product_name}")
    print(f"  Serial: {dev.descriptor.serial_number}")
    print(f"  VID:PID: {dev.descriptor.vid:04x}:{dev.descriptor.pid:04x}")

    print(f"\nRP ID:   {fido2_cfg.get('rp_id', 'credential-gate.local')}")
    print(f"RP Name: {fido2_cfg.get('rp_name', 'Credential Gate')}")
    print(f"Store:   {fido2_cfg.get('credential_store')}")

    if "--no-confirm" not in sys.argv:
        input("\nPress Enter to begin registration (or Ctrl+C to cancel)...")

    try:
        cred = register(
            rp_id=fido2_cfg.get("rp_id", "credential-gate.local"),
            rp_name=fido2_cfg.get("rp_name", "Credential Gate"),
            store_path=fido2_cfg.get("credential_store"),
        )
        print("\nRegistration successful.")
        print(f"Credential ID: {cred.credential_id.hex()}")
        print("\nYou can now start the service with: python main.py")
    except Exception as e:
        print(f"\nRegistration failed: {e}")
        sys.exit(1)


def cmd_gen_key():
    """Generate a random API key for agent configuration."""
    key = secrets.token_urlsafe(32)
    print(f"Generated API key: {key}")
    print("\nAdd this to your config.yaml under the agent entry:")
    print(f'  api_key: "{key}"')


def cmd_check():
    """Run pre-flight checks."""
    import shutil

    from bitwarden import keychain_retrieve
    from fido import FIDO2_AVAILABLE

    cfg = load_config()

    # Phase 12: Security tier
    tier = cfg.get("security_tier", "gold")

    print("Credential Gate — Pre-flight Check")
    print("=" * 40)

    # Python
    print(f"\nPython: {sys.version.split()[0]}")
    print(f"Security tier: {tier.upper()}")

    # FIDO2 devices (only check for gold tier)
    if tier == "gold":
        if not FIDO2_AVAILABLE:
            print("YubiKey: FIDO2 library NOT INSTALLED — pip install fido2")
        else:
            from fido import list_devices, get_registered_credentials
            devices = list_devices()
            if devices:
                dev = devices[0]
                print(f"YubiKey: {dev.descriptor.product_name} (serial={dev.descriptor.serial_number})")
            else:
                print("YubiKey: NOT FOUND")

            # Registered credentials
            fido2_cfg = cfg.get("fido2", {})
            store = fido2_cfg.get("credential_store", "")
            creds = get_registered_credentials(store)
            print(f"Registered credentials: {len(creds)}")
    else:
        print(f"YubiKey: not required (silver tier)")
        print(f"python-fido2: {'installed' if FIDO2_AVAILABLE else 'not installed (OK for silver tier)'}")

    # Bitwarden CLI
    bw_path = shutil.which("bw")
    if bw_path:
        import subprocess
        ver = subprocess.run([bw_path, "--version"], capture_output=True, text=True)
        print(f"Bitwarden CLI: {ver.stdout.strip()} ({bw_path})")
    else:
        print("Bitwarden CLI: NOT FOUND")

    # Keychain entries
    bw_cfg = cfg.get("bitwarden", {})
    kc_service = bw_cfg.get("keychain_service", "credential-gate")
    kc_account = bw_cfg.get("keychain_account", "bitwarden")
    has_bw_pw = keychain_retrieve(kc_service, kc_account) is not None
    print(f"Keychain (BW password): {'STORED' if has_bw_pw else 'NOT SET — run: python setup.py store-password'}")

    # Authorization mode
    mode = cfg.get("authorization", {}).get("mode", "yubikey")
    print(f"Authorization mode: {mode}")

    # Ntfy status
    notif_cfg = cfg.get("notifications", {})
    if notif_cfg.get("enabled", False):
        ntfy_server = notif_cfg.get("ntfy_server", "")
        ntfy_topic = notif_cfg.get("ntfy_topic", "")
        callback_url = notif_cfg.get("callback_base_url", "")
        print(f"Ntfy server: {ntfy_server}")
        print(f"Ntfy topic: {ntfy_topic}")
        print(f"Callback URL: {callback_url}")
        if not ntfy_server or not ntfy_topic:
            print("  WARNING: Ntfy not fully configured")
        if "CHANGEME" in ntfy_topic:
            print("  WARNING: Ntfy topic still has placeholder value")
    else:
        print("Notifications: disabled")

    # Config
    agents = cfg.get("agents", {})
    print(f"Configured agents: {', '.join(agents.keys()) or 'none'}")

    # Check for placeholder API keys
    for name, agent in agents.items():
        key = agent.get("api_key", "")
        if "CHANGE_ME" in key:
            print(f"  WARNING: Agent '{name}' still has placeholder API key")

    # Policy files
    from pathlib import Path
    from policy import validate_policy_file

    policies_cfg = cfg.get("policies", {})
    policies_dir = Path(policies_cfg.get("directory", "policies"))
    default_policy = policies_cfg.get("default_policy", "deny")
    print(f"\nPolicies directory: {policies_dir}")
    print(f"Default policy: {default_policy}")

    if policies_dir.exists():
        policy_files = sorted(policies_dir.glob("*.yaml"))
        if policy_files:
            for pf in policy_files:
                agent_name = pf.stem
                errors = validate_policy_file(pf)
                if errors:
                    print(f"  Policy '{agent_name}': INVALID")
                    for err in errors:
                        print(f"    - {err}")
                else:
                    print(f"  Policy '{agent_name}': valid")

            # Check that all configured agents have policy files
            policy_agents = {pf.stem for pf in policy_files}
            for agent_name in agents:
                if agent_name not in policy_agents:
                    if default_policy == "deny":
                        print(f"  WARNING: Agent '{agent_name}' has no policy file (will be denied)")
                    else:
                        print(f"  INFO: Agent '{agent_name}' has no policy file (allow_all)")
        else:
            print("  No policy files found")
            if default_policy == "deny":
                print("  WARNING: All agents will be denied (default_policy=deny)")
    else:
        print(f"  WARNING: Policies directory '{policies_dir}' does not exist")

    print(f"\nServer: {cfg['server']['host']}:{cfg['server']['port']}")
    print(f"Audit DB: {cfg['audit']['db_path']}")


def cmd_store_password():
    """Store the Bitwarden master password in macOS Keychain."""
    from bitwarden import keychain_store, keychain_retrieve

    cfg = load_config()
    bw_cfg = cfg.get("bitwarden", {})
    service = bw_cfg.get("keychain_service", "credential-gate")
    account = bw_cfg.get("keychain_account", "bitwarden")

    print("Credential Gate — Store Bitwarden Master Password")
    print("=" * 50)
    print(f"\nKeychain service: {service}")
    print(f"Keychain account: {account}")

    # Check if already stored
    existing = keychain_retrieve(service, account)
    if existing:
        print("\nA password is already stored in Keychain for this entry.")
        confirm = input("Overwrite? [y/N] ").strip().lower()
        if confirm != "y":
            print("Aborted.")
            return

    password = getpass.getpass("\nBitwarden master password: ")
    if not password:
        print("ERROR: Password cannot be empty.")
        sys.exit(1)

    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("ERROR: Passwords do not match.")
        sys.exit(1)

    keychain_store(service, account, password)
    print("\nPassword stored in macOS Keychain.")
    print("The service will use this to unlock Bitwarden automatically.")


def cmd_test_ntfy():
    """Send a test notification to verify Ntfy.sh connectivity."""
    from notifications import test_ntfy

    cfg = load_config()
    notif_cfg = cfg.get("notifications", {})

    print("Credential Gate — Test Ntfy Notification")
    print("=" * 40)

    if not notif_cfg.get("enabled", False):
        print("\nNotifications are disabled in config.yaml.")
        print("Set notifications.enabled to true and try again.")
        sys.exit(1)

    ntfy_server = notif_cfg.get("ntfy_server", "")
    ntfy_topic = notif_cfg.get("ntfy_topic", "")

    if not ntfy_server or not ntfy_topic:
        print("\nNtfy server or topic not configured in config.yaml.")
        sys.exit(1)

    print(f"\nServer: {ntfy_server}")
    print(f"Topic:  {ntfy_topic}")
    print("Sending test notification...")

    if test_ntfy(cfg):
        print("\nTest notification sent successfully!")
        print("Check the Ntfy app on your phone for the notification.")
    else:
        print("\nFailed to send test notification.")
        print("Check your ntfy_server and ntfy_topic settings in config.yaml.")
        sys.exit(1)


def cmd_test_phone():
    """Test the phone-only approval flow end-to-end.

    Sends a test approval request via Ntfy with Approve/Deny buttons.
    Confirms that the phone can reach the callback URL and trigger
    the approval.  Useful for verifying silver tier (phone-only) setup.
    """
    import time

    from approvals import ApprovalQueue, ApprovalState
    from notifications import send_approval_notification

    cfg = load_config()
    notif_cfg = cfg.get("notifications", {})

    print("Credential Gate — Test Phone Approval Flow")
    print("=" * 50)

    tier = cfg.get("security_tier", "gold")
    print(f"\nSecurity tier: {tier}")

    if not notif_cfg.get("enabled", False):
        print("\nNotifications are disabled in config.yaml.")
        print("Phone approval requires notifications. Enable them first.")
        sys.exit(1)

    callback_url = notif_cfg.get("callback_base_url", "")
    if not callback_url:
        print("\nNo callback_base_url configured.")
        print("Phone approval buttons need to reach this URL.")
        sys.exit(1)

    print(f"Ntfy server:  {notif_cfg.get('ntfy_server', '')}")
    print(f"Ntfy topic:   {notif_cfg.get('ntfy_topic', '')}")
    print(f"Callback URL: {callback_url}")

    queue = ApprovalQueue()
    pending = queue.create(
        agent_id="test-phone-setup",
        credential_name="test-credential",
        purpose="Phone approval test from setup.py",
        fields=["password"],
    )

    print(f"\nSending approval request (ID: {pending.request_id[:12]}...)")

    sent = send_approval_notification(
        config=cfg,
        request_id=pending.request_id,
        agent_id="test-phone-setup",
        credential_name="test-credential",
        purpose="Phone approval test — tap APPROVE to confirm",
    )

    if not sent:
        print("Failed to send notification. Check Ntfy settings.")
        sys.exit(1)

    print("Notification sent! Check your phone.")
    print(f"\nWaiting up to 60 seconds for phone approval...")
    print("  Tap APPROVE on your phone to complete the test.")
    print("  Tap DENY or wait 60s to test denial flow.\n")

    # Note: this test works without the server running because
    # the callback URL is just for Ntfy to know where to send the
    # HTTP request. The actual queue.wait here simulates the server.
    # In real operation, the server's /approve/{id} endpoint handles it.
    print("(For this test to work, the Credential Gate server must be running")
    print(f" at {callback_url} so Ntfy can reach the /approve endpoint.)\n")

    state = queue.wait(pending.request_id, timeout=60)

    if state == ApprovalState.APPROVED:
        print("Phone approval SUCCEEDED!")
        print("Your phone-only setup is working correctly.")
    elif state == ApprovalState.DENIED:
        print("Phone approval was DENIED (expected if you tapped Deny).")
        print("The denial flow is working correctly.")
    else:
        print("Phone approval TIMED OUT.")
        print("\nPossible issues:")
        print(f"  1. Is the Credential Gate server running at {callback_url}?")
        print("  2. Can Ntfy reach the callback URL? (must be network-accessible)")
        print("  3. Did you receive the notification on your phone?")
        print("  4. Check the Ntfy topic subscription in the Ntfy app.")
        sys.exit(1)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    commands = {
        "register": cmd_register,
        "gen-key": cmd_gen_key,
        "check": cmd_check,
        "store-password": cmd_store_password,
        "test-ntfy": cmd_test_ntfy,
        "test-phone": cmd_test_phone,
    }

    fn = commands.get(cmd)
    if not fn:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)

    fn()


if __name__ == "__main__":
    main()
