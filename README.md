# Credential Gate

**Hardware YubiKey authorization gate for AI agent credential access.**

When an AI agent needs a secret from your Bitwarden vault, it calls this service's API. Your YubiKey lights up. You touch it. The credential is released. Without your physical touch, the agent gets nothing.

This is `sudo` for AI agents — but with a hardware factor instead of a password.

## Why

AI agents need credentials to do useful work — API keys, tokens, passwords. But giving agents static, long-lived secrets creates the same attack surface that enables supply chain compromises (see: [axios npm attack, March 2026](https://github.com/theNetworkChuck/axios-attack-guide)).

Credential Gate solves this by requiring a **physical hardware key touch** for every credential request. No software compromise can bypass a physical factor.

```
┌──────────┐     ┌────────────────────┐     ┌───────────┐
│ AI Agent │────▶│ Credential Gate    │────▶│ Bitwarden │
│          │     │ Service (local)    │     │ Vault     │
└──────────┘     │                    │     └───────────┘
                 │ 1. Receive request │
                 │ 2. FIDO2 challenge │
                 │ 3. Wait for touch  │──▶ 🔑 YubiKey
                 │ 4. Auth to BW      │
                 │ 5. Return secret   │
                 │ 6. Log everything  │
                 └────────────────────┘
```

## Features

- **FIDO2/CTAP2 hardware key verification** — YubiKey touch required for every credential request
- **Bitwarden CLI integration** — fetches secrets from your existing vault
- **Session management** — automatic Bitwarden unlock/refresh via macOS Keychain
- **Push notifications** — Home Assistant alerts your phone when a touch is waiting
- **Full audit log** — every request logged to SQLite (agent, credential, purpose, approval/denial)
- **API key auth** — per-agent API keys with configurable credential access
- **Graceful degradation** — clear health reporting, never crashes on missing config
- **launchd service** — auto-starts on boot, restarts on crash

## Requirements

- macOS (uses IOKit for HID transport, macOS Keychain for secret storage)
- Python 3.10+
- A FIDO2-compatible security key (YubiKey 5 series, etc.)
- [Bitwarden CLI](https://bitwarden.com/help/cli/) (`brew install bitwarden-cli`)
- A Bitwarden account with the credentials your agents need

## Quick Start

```bash
# Clone and install
git clone https://github.com/ped-ro/credential-gate.git
cd credential-gate
pip install -r requirements.txt

# Copy and edit config
cp config.example.yaml config.yaml
# Edit config.yaml — set your agent API keys

# Register your YubiKey (one-time, key must be plugged in)
python setup.py register

# Generate an API key for your agent
python setup.py gen-key

# Store your Bitwarden master password in macOS Keychain
python setup.py store-password

# (Optional) Store Home Assistant token for push notifications
python setup.py store-ha-token

# Verify setup
python setup.py check

# Start the service
python main.py
```

## API

### `POST /credential`

Request a credential. Triggers YubiKey touch.

```bash
curl -X POST http://127.0.0.1:8200/credential \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_AGENT_API_KEY" \
  -d '{
    "agent_id": "my-agent",
    "credential_name": "github-deploy-token",
    "purpose": "deploying vault-mcp update",
    "fields": ["password"]
  }'
```

**Response (approved):**
```json
{
  "status": "approved",
  "credential": {
    "password": "the-actual-secret"
  }
}
```

**Response (denied/timeout):**
```json
{
  "status": "denied",
  "reason": "timeout"
}
```

### `GET /health`

```json
{
  "status": "ok",
  "bitwarden": "active",
  "fido2": "ready",
  "notifications": "enabled"
}
```

### `GET /audit`

Returns recent audit log entries.

## Running as a Service

Install the launchd agent to auto-start on boot:

```bash
./install-service.sh    # Install and start
./restart-service.sh    # Restart
./uninstall-service.sh  # Stop and remove
```

Logs: `logs/credential-gate.log`

## Configuration

Copy `config.example.yaml` to `config.yaml` and edit:

- **agents** — define API keys and allowed credentials per agent
- **bitwarden** — Keychain settings, session refresh interval
- **fido2** — relying party ID and name
- **timeouts** — how long to wait for YubiKey touch
- **notifications** — Home Assistant URL for push notifications

## Security Design

- **Localhost only** — binds to 127.0.0.1, not accessible from the network
- **Never caches credentials** — fetches fresh from Bitwarden on every approved request
- **Never logs credential values** — only names, fields requested, and approval status
- **Fails closed** — any error in FIDO2 or Bitwarden flow = deny the request
- **Secrets in Keychain** — Bitwarden master password and HA token stored in macOS Keychain, never on disk
- **Per-agent API keys** — each agent authenticates with its own key
- **Full audit trail** — every request logged with timestamp, agent, credential, purpose, and outcome

## Adapting for Linux

The core FIDO2 flow uses `python-fido2` which supports Linux via `/dev/hidraw*`. You'd need to:

1. Replace macOS Keychain calls (`security` CLI) with `secret-tool` (GNOME Keyring) or `pass`
2. Replace launchd with a systemd service unit
3. Ensure your user has permission to access HID devices (`udev` rules)

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

Inspired by the [axios npm supply chain attack](https://github.com/theNetworkChuck/axios-attack-guide) (March 31, 2026), which demonstrated why long-lived credentials without physical authorization gates are a fundamental security weakness.
