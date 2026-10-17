# npm-lifecycle-hook-auditor

**Installing a package should not install a backdoor.**

On October 8, 2026, `tensorlake@0.5.144` was compromised through its npm **preinstall hook**: merely installing the package executed an obfuscated loader through the Bun runtime, harvesting npm, GitHub, AWS, Vault, Kubernetes, and SSH credentials, `.env` files, and crypto wallets — and specifically targeting `.claude`, `.cursor`, `.kiro`, Windsurf, and Zed configs. The malicious commit sat in the repo for 20 hours before the release. `npm audit` checks known vulnerabilities; it never checks what install hooks **do**.

This tool audits npm package lifecycle scripts (`preinstall`, `install`, `postinstall`) in `package.json` files and tarball file lists: it enumerates declared hooks and flags obfuscation, exfiltration patterns, Bun-runtime invocation, and Shai-Hulud markers (`WORMTAG` globals, `setup.mjs`-style loaders).

## What it flags

| Flag | Severity | Meaning |
|------|----------|---------|
| `WORMTAG_MARKER` | CRITICAL | Shai-Hulud worm marker (Oct 2026 tensorlake payload) |
| `KNOWN_LOADER` | CRITICAL | Filename matches the Shai-Hulud loader chain |
| `SECRET_HARVEST` | HIGH | Reads `.npmrc`, `.env`, SSH keys, cloud secrets |
| `AGENT_CONFIG_TARGET` | HIGH | Targets agent IDE configs (`.claude`, `.cursor`, …) |
| `BUN_RUNTIME` | HIGH | Invokes Bun — the loader's dodge around node monitoring |
| `PERSISTENCE` | HIGH | Installs cron/launchd/systemd persistence |
| `OBFUSCATED` | HIGH | High-entropy payload — likely obfuscated |
| `NETWORK_CALL` / `CURL_PIPE_SH` | MEDIUM | Install-time network activity |

## Usage

```bash
python3 npm_lifecycle_hook_auditor.py --package-json package.json
python3 npm_lifecycle_hook_auditor.py --package-json package.json --files package/lib/setup.mjs --json
```

## Remediation order matters

Socket documented a **dead-man switch**: revoking a stolen GitHub token while the monitor still runs triggers a wipe of the home directory. If compromise is confirmed: **kill the process first, then revoke tokens.**

## What this does NOT do

- Static analysis only — it flags suspicious patterns; it cannot prove a hook is malicious.
- A clean result is not a safety certification.

Python standard library only. No network, no dependencies.

## Built by Ingenious AI

This tool is built and maintained by **Ingenious AI**. Get early access to our AI security platforms:

- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DisclosureGuard
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ModelMinder
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20TermsWatch
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Vibe-Code%20Audit
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20BreachHunter
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ChatBreaker
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DomainGuard
- https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ContentCraft%20AI
