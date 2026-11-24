"""Baseline persistence, HMAC verification, and integrity diff engine."""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

from fim_guard.crypto import sign_payload, verify_signature
from fim_guard.models import Baseline, FileRecord, IntegrityChange, IntegrityReport
from fim_guard.scanner import scan_directory

BASELINE_VERSION = 1
DEFAULT_BASELINE_NAME = ".fim_baseline.json"


class BaselineTamperedError(Exception):
    """Raised when the baseline HMAC signature fails verification."""


class BaselineFormatError(Exception):
    """Raised when the baseline file cannot be read or parsed."""


def _baseline_body(
    version: int,
    created_at: str,
    root_dir: str,
    files: dict[str, FileRecord],
) -> dict[str, Any]:
    return {
        "version": version,
        "created_at": created_at,
        "root_dir": root_dir,
        "files": {
            path: {
                "sha256": rec.sha256,
                "size": rec.size,
                "mode": rec.mode,
            }
            for path, rec in sorted(files.items())
        },
    }


def create_baseline(
    root_dir: Path,
    baseline_path: Path,
    secret_key: str | None = None,
    ignored_dirs: set[str] | None = None,
) -> Baseline:
    """Scan root_dir and save a (optionally HMAC-signed) JSON baseline."""
    files = scan_directory(
        root_dir=root_dir,
        exclude_paths={baseline_path},
        ignored_dirs=ignored_dirs,
    )
    created_at = datetime.now(timezone.utc).isoformat()
    root_str = str(root_dir.resolve())
    body = _baseline_body(BASELINE_VERSION, created_at, root_str, files)
    signature = sign_payload(body, secret_key) if secret_key else None

    document: dict[str, Any] = {**body, "hmac_sha256": signature}
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(json.dumps(document, indent=2), encoding="utf-8")

    return Baseline(
        version=BASELINE_VERSION,
        created_at=created_at,
        root_dir=root_str,
        files=files,
        hmac_sha256=signature,
    )


def load_baseline(baseline_path: Path) -> tuple[Baseline, dict[str, Any]]:
    """Read and parse a baseline JSON file."""
    try:
        raw = json.loads(baseline_path.read_text(encoding="utf-8"))
        files = {
            path: FileRecord(
                path=path,
                sha256=str(meta["sha256"]),
                size=int(meta["size"]),
                mode=str(meta["mode"]),
            )
            for path, meta in raw["files"].items()
        }
        baseline = Baseline(
            version=int(raw["version"]),
            created_at=str(raw["created_at"]),
            root_dir=str(raw["root_dir"]),
            files=files,
            hmac_sha256=raw.get("hmac_sha256"),
        )
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise BaselineFormatError(f"No se pudo leer la línea base: {exc}") from exc

    body = _baseline_body(
        baseline.version,
        baseline.created_at,
        baseline.root_dir,
        baseline.files,
    )
    return baseline, body


def check_integrity(
    root_dir: Path,
    baseline_path: Path,
    secret_key: str | None = None,
    ignored_dirs: set[str] | None = None,
) -> IntegrityReport:
    """Verify baseline signature and compare current files against recorded hashes."""
    baseline, body = load_baseline(baseline_path)

    if baseline.hmac_sha256 is not None:
        if not secret_key or not verify_signature(body, secret_key, baseline.hmac_sha256):
            raise BaselineTamperedError(
                "¡ALERTA CRÍTICA! La firma HMAC de la línea base no coincide (posible manipulación o clave incorrecta)."
            )
        signature_status = "verified"
    elif secret_key:
        raise BaselineTamperedError(
            "Se proporcionó clave HMAC, pero el archivo de línea base no tiene firma."
        )
    else:
        signature_status = "unsigned"

    current_files = scan_directory(
        root_dir=root_dir,
        exclude_paths={baseline_path},
        ignored_dirs=ignored_dirs,
    )

    changes: list[IntegrityChange] = []
    baseline_paths = set(baseline.files.keys())
    current_paths = set(current_files.keys())

    for path in sorted(baseline_paths - current_paths):
        changes.append(
            IntegrityChange(
                path=path,
                change_type="deleted",
                severity="HIGH",
                detail="Archivo eliminado del directorio monitoreado.",
            )
        )

    for path in sorted(current_paths - baseline_paths):
        changes.append(
            IntegrityChange(
                path=path,
                change_type="added",
                severity="MEDIUM",
                detail="Archivo nuevo no registrado en la línea base.",
            )
        )

    for path in sorted(baseline_paths & current_paths):
        old = baseline.files[path]
        new = current_files[path]
        if old.sha256 != new.sha256:
            changes.append(
                IntegrityChange(
                    path=path,
                    change_type="modified",
                    severity="HIGH",
                    detail=f"Hash SHA-256 modificado ({old.sha256[:12]}… → {new.sha256[:12]}…).",
                )
            )
        elif old.mode != new.mode:
            changes.append(
                IntegrityChange(
                    path=path,
                    change_type="permissions_changed",
                    severity="MEDIUM",
                    detail=f"Permisos alterados ({old.mode} → {new.mode}).",
                )
            )

    return IntegrityReport(
        root_dir=str(root_dir.resolve()),
        checked_files=len(current_files),
        signature_status=signature_status,
        changes=changes,
    )
