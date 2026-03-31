#!/usr/bin/env python3
"""Credential Gate — setup and administration.

Usage:
    python setup.py register         Register a YubiKey for FIDO2 assertion
    python setup.py gen-key          Generate an API key for an agent
    python setup.py check            Verify device, config, and service status
    python setup.py store-password   Store Bitwarden master password in Keychain
    python setup.py test-ntfy        Send a test notification via Ntfy
"""

import getpass
import secrets
import sys

from config import load_config


def cmd_register():
    """Register a YubiKey with the Credential Gate service."""
    from fido import register, list_devices

    cfg = load_config()
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

    cfg = load_config()

    print("Credential Gate — Pre-flight Check")
    print("=" * 40)

    # Python
    print(f"\nPython: {sys.version.split()[0]}")

    # FIDO2 devices
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
    }

    fn = commands.get(cmd)
    if not fn:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)

    fn()


if __name__ == "__main__":
    main()
