"""npm-lifecycle-hook-auditor
==========================

In October 2026, tensorlake@0.5.144 was compromised through its npm
preinstall hook: installing the package executed an obfuscated loader
through the Bun runtime, harvesting npm/GitHub/AWS/Vault/Kubernetes/
SSH credentials, .env files, and crypto wallets — and targeting
.claude/.cursor/.kiro/Windsurf/Zed configs. npm-audit checks known
vulnerabilities; it does not check what install hooks DO.

This tool audits npm package lifecycle scripts (preinstall,
postinstall, install) in package.json files and tarball file lists:
it enumerates declared hooks and flags obfuscation, exfiltration
patterns, Bun-runtime invocation, and Shai-Hulud markers (WORMTAG
globals, setup.mjs-style loaders). stdlib only.

It also warns about the dead-man-switch pattern Socket documented:
revoking a stolen GitHub token while the monitor still runs can
trigger a destructive wipe — so remediation order matters.

What this does NOT do: it is static analysis, not execution. It
flags suspicious patterns; it cannot prove a hook is malicious, and
a clean result is not a safety certification.
"""

import argparse
import json
import math
import re
import sys

HOOK_KEYS = ("preinstall", "install", "postinstall",
             "prepublishOnly", "prepare")

# (flag, severity, description)
PATTERNS = (
    (re.compile(r"WORMTAG", re.I), "WORMTAG_MARKER", "CRITICAL",
     "Shai-Hulud worm marker — matches the Oct 2026 tensorlake "
     "compromise payload signature."),
    (re.compile(r"\bbun\b", re.I), "BUN_RUNTIME", "HIGH",
     "Invokes the Bun runtime — the tensorlake loader ran through "
     "Bun to dodge node-based monitoring."),
    (re.compile(r"setup\.mjs|Math_Symbol\.js", re.I), "KNOWN_LOADER",
     "CRITICAL",
     "Filename matches the tensorlake/Shai-Hulud loader chain."),
    (re.compile(r"(fetch|axios|https?\.get|XMLHttpRequest)\s*\(",
                re.I), "NETWORK_CALL", "MEDIUM",
     "Makes network calls at install time — install scripts should "
     "not phone home."),
    (re.compile(r"\.npmrc|\.env\b|id_rsa|\.ssh|AWS_SECRET|VAULT_TOKEN",
                re.I), "SECRET_HARVEST", "HIGH",
     "Reads credential material (.npmrc, .env, SSH keys, cloud "
     "secrets) — the exact harvest list in the Oct 2026 campaign."),
    (re.compile(r"crontab|launchd|systemd|HKCU.*Run", re.I),
     "PERSISTENCE", "HIGH",
     "Installs persistence — install hooks should never do this."),
    (re.compile(r"curl[^|]*\|\s*(ba)?sh", re.I), "CURL_PIPE_SH",
     "MEDIUM",
     "curl-piped-to-shell — classic remote payload fetch."),
)

AGENT_CONFIG_TARGETS = (".claude", ".cursor", ".kiro", "windsurf", "zed")


def shannon_entropy(text):
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def analyze_script(script_text):
    """Analyze one hook script. Returns a list of findings."""
    script = script_text or ""
    findings = []
    for rx, flag, severity, desc in PATTERNS:
        if rx.search(script):
            findings.append({"flag": flag, "severity": severity,
                             "description": desc})
    if len(script) > 200 and shannon_entropy(script) > 5.5:
        findings.append({"flag": "OBFUSCATED", "severity": "HIGH",
                         "description": "High-entropy payload — likely "
                                        "obfuscated JavaScript."})
    for target in AGENT_CONFIG_TARGETS:
        if target in script.lower():
            findings.append(
                {"flag": "AGENT_CONFIG_TARGET", "severity": "HIGH",
                 "description": "References agent IDE config dir '%s' — "
                                "the Oct 2026 campaign harvested these."
                                % target})
            break
    return findings


def parse_hooks(package_json_text):
    """Extract declared lifecycle hooks from package.json text."""
    try:
        pkg = json.loads(package_json_text)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid package.json: %s" % exc)
    scripts = pkg.get("scripts") or {}
    if not isinstance(scripts, dict):
        return {}
    return {k: str(v) for k, v in scripts.items() if k in HOOK_KEYS}


def audit_package(package_json_text, file_list=()):
    """Audit a package: hooks + tarball file list. Deterministic."""
    hooks = parse_hooks(package_json_text)
    findings = []
    for hook, script in hooks.items():
        for f in analyze_script(script):
            f = dict(f)
            f["hook"] = hook
            findings.append(f)
    for name in file_list or ():
        base = str(name).split("/")[-1]
        if re.search(r"setup\.mjs|Math_Symbol\.js", base, re.I):
            findings.append({"flag": "KNOWN_LOADER", "severity": "CRITICAL",
                             "hook": "(tarball file)",
                             "description": "Tarball contains a file "
                                            "matching the Shai-Hulud "
                                            "loader chain."})
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    findings.sort(key=lambda f: order.get(f["severity"], 3))
    worst = findings[0]["severity"] if findings else "CLEAN"
    return {
        "hooks": hooks,
        "worst": worst,
        "findings": findings,
        "remediation_note": (
            "If compromise is confirmed: kill the process FIRST, then "
            "revoke tokens — Socket documented a dead-man switch that "
            "wipes the home directory when a stolen GitHub token is "
            "revoked while the monitor still runs. Remediation order "
            "matters."),
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Audit npm lifecycle hooks for install-time malware.")
    ap.add_argument("--package-json", required=True,
                    help="path to package.json")
    ap.add_argument("--files", nargs="*", default=[],
                    help="tarball file list to scan for known loaders")
    ap.add_argument("--json", action="store_true",
                    help="emit JSON instead of text")
    args = ap.parse_args(argv)
    try:
        with open(args.package_json, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    try:
        report = audit_package(text, args.files)
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("Worst finding: %s" % report["worst"])
        for f in report["findings"]:
            print("[%s] %s (%s): %s" % (f["severity"], f["flag"],
                                        f["hook"], f["description"]))
        if not report["findings"]:
            print("No lifecycle hooks declared or no suspicious "
                  "patterns found — not a safety certification.")
    return 1 if report["worst"] in ("CRITICAL", "HIGH") else 0


if __name__ == "__main__":
    sys.exit(main())
