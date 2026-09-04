"""Run the real Inno control flow against inert component scripts, never Keeper."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]
COMPILER = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs/Inno Setup 6/ISCC.exe"


@pytest.mark.skipif(os.name != "nt" or not COMPILER.is_file(), reason="Windows Inno compiler required")
@pytest.mark.parametrize("authority_code,user_code", [(0, 0), (42, 0), (0, 9)])
def test_real_wizard_checks_exit_codes_and_gates_user_phase(tmp_path, authority_code, user_code):
    payload = tmp_path / "payload"
    payload.mkdir()
    marker = tmp_path / "phases.txt"
    for filename, phase, code in [
        ("install-machine-authority.ps1", "authority", authority_code),
        ("install-user-components.ps1", "user", user_code),
    ]:
        (payload / filename).write_text(
            "param([string]$PayloadRoot)\n"
            f"Add-Content -LiteralPath '{marker}' -Value '{phase}'\nexit {code}\n"
        )
    # Use precisely the production Pascal code and file extraction layout.
    # Only the test wrapper's privileges/payload are different; no service or
    # real product paths are accessible to these inert fixture scripts.
    production = (ROOT / "packaging/windows/keeper-machine.iss").read_text()
    code = production.split("[Code]", 1)[1]
    definition = tmp_path / "fixture.iss"
    definition.write_text(
        "[Setup]\nAppName=Keeper installer control-flow test\nAppVersion=0.0.0\n"
        "PrivilegesRequired=lowest\nUninstallable=no\nCreateAppDir=no\n"
        "DisableDirPage=yes\nDisableProgramGroupPage=yes\n"
        f"OutputDir={tmp_path}\nOutputBaseFilename=fixture\n"
        "[Files]\n"
        f'Source: "{payload}\\*"; DestDir: "{{tmp}}\\KeeperMachinePayload"; Flags: recursesubdirs createallsubdirs dontcopy noencryption\n'
        "[Code]\n" + code
    )
    compiled = subprocess.run([str(COMPILER), str(definition)], capture_output=True, text=True, timeout=60)
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    log = tmp_path / "setup.log"
    result = subprocess.run(
        [str(tmp_path / "fixture.exe"), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", f"/LOG={log}"],
        capture_output=True, text=True, timeout=60,
    )
    assert marker.read_text().splitlines() == (["authority"] if authority_code else ["authority", "user"])
    if authority_code or user_code:
        # Inno's documented PrepareToInstall failure code (not success).
        assert result.returncode == 7, log.read_text()
        assert "Keeper setup is incomplete" in log.read_text()
    else:
        assert result.returncode == 0, log.read_text()


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell required")
@pytest.mark.parametrize("host_code,desktop_throws", [(3, False), (0, True), (0, False)])
def test_real_user_script_never_runs_desktop_after_host_failure(tmp_path, host_code, desktop_throws):
    import sys

    payload = tmp_path / "payload"
    (payload / "desktop").mkdir(parents=True)
    (payload / "source").mkdir()
    marker = tmp_path / "desktop-called.txt"
    (payload / "keeper-machine-user-setup.py").write_text(f"raise SystemExit({host_code})\n")
    (payload / "desktop/install-keeper-desktop.ps1").write_text(
        f"Set-Content -LiteralPath '{marker}' -Value called\n" +
        ("throw 'desktop fixture failed'\n" if desktop_throws else "")
    )
    script = (ROOT / "scripts/install-keeper-machine-user.ps1").read_text()
    script = script.replace('$Python = Join-Path $PayloadRoot "runtime\\python.exe"', f"$Python = '{sys.executable}'")
    test_script = tmp_path / "fixture.ps1"
    test_script.write_text(script)
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(test_script), "-PayloadRoot", str(payload)],
        env={**os.environ, "TEMP": str(tmp_path)}, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == (1 if host_code or desktop_throws else 0), result.stdout + result.stderr
    assert marker.exists() is (host_code == 0)
    logs = list(tmp_path.glob("Keeper-machine-user-*.log"))
    assert len(logs) == 1
    if host_code or desktop_throws:
        assert "verified successfully" not in logs[0].read_text(encoding="utf-8-sig")
