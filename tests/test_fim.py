"""Unit and security tests for fim-guard using pytest's isolated tmp_path."""

import json
import os
from pathlib import Path

import pytest

from fim_guard.baseline import (
    BaselineTamperedError,
    check_integrity,
    create_baseline,
)


def test_clean_directory_passes_integrity_check_with_hmac(tmp_path: Path) -> None:
    watched = tmp_path / "etc_sim"
    watched.mkdir()
    (watched / "config.conf").write_text("port=22\npermit_root=no\n", encoding="utf-8")
    (watched / "nested").mkdir()
    (watched / "nested" / "rules.txt").write_text("allow 443\n", encoding="utf-8")

    baseline_path = tmp_path / "baseline.json"
    key = "clave-super-secreta-de-prueba"

    baseline = create_baseline(watched, baseline_path, secret_key=key)
    assert len(baseline.files) == 2
    assert baseline.hmac_sha256 is not None

    report = check_integrity(watched, baseline_path, secret_key=key)
    assert report.is_clean is True
    assert report.signature_status == "verified"
    assert report.checked_files == 2


def test_detects_modified_deleted_added_and_permission_changes(tmp_path: Path) -> None:
    watched = tmp_path / "app"
    watched.mkdir()
    f_mod = watched / "main.py"
    f_del = watched / "old.txt"
    f_perm = watched / "script.sh"

    f_mod.write_text("print('v1')", encoding="utf-8")
    f_del.write_text("to-delete", encoding="utf-8")
    f_perm.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    os.chmod(f_perm, 0o644)

    baseline_path = watched / ".fim_baseline.json"
    create_baseline(watched, baseline_path)

    # Simulate tampering
    f_mod.write_text("print('backdoor')", encoding="utf-8")
    f_del.unlink()
    os.chmod(f_perm, 0o755)
    (watched / "webshell.php").write_text("<?php echo 1; ?>", encoding="utf-8")

    report = check_integrity(watched, baseline_path)
    assert report.is_clean is False
    by_path = {c.path: c for c in report.changes}

    assert by_path["main.py"].change_type == "modified"
    assert by_path["main.py"].severity == "HIGH"
    assert by_path["old.txt"].change_type == "deleted"
    assert by_path["old.txt"].severity == "HIGH"
    assert by_path["script.sh"].change_type == "permissions_changed"
    assert by_path["script.sh"].severity == "MEDIUM"
    assert by_path["webshell.php"].change_type == "added"
    assert by_path["webshell.php"].severity == "MEDIUM"


def test_tampered_baseline_triggers_hmac_alert(tmp_path: Path) -> None:
    watched = tmp_path / "secure"
    watched.mkdir()
    target_file = watched / "passwd.sim"
    target_file.write_text("root:x:0:0\n", encoding="utf-8")

    baseline_path = tmp_path / "baseline.json"
    key = "llave-hmac-segura"
    create_baseline(watched, baseline_path, secret_key=key)

    # Attacker modifies the file AND tries to forge its hash inside baseline.json
    target_file.write_text("root:x:0:0\nattacker:x:0:0\n", encoding="utf-8")
    doc = json.loads(baseline_path.read_text(encoding="utf-8"))
    doc["files"]["passwd.sim"]["sha256"] = "0" * 64
    baseline_path.write_text(json.dumps(doc), encoding="utf-8")

    with pytest.raises(BaselineTamperedError):
        check_integrity(watched, baseline_path, secret_key=key)


def test_symlinks_are_ignored_for_safety(tmp_path: Path) -> None:
    watched = tmp_path / "watched"
    watched.mkdir()
    real_file = watched / "real.txt"
    real_file.write_text("ok", encoding="utf-8")
    (watched / "loop_link.txt").symlink_to(real_file)

    baseline_path = tmp_path / "baseline.json"
    baseline = create_baseline(watched, baseline_path)
    assert list(baseline.files.keys()) == ["real.txt"]
