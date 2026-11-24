"""Typed data models for file records, baselines, and integrity reports."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class FileRecord:
    """Cryptographic and metadata snapshot of a single file."""

    path: str
    sha256: str
    size: int
    mode: str


@dataclass(frozen=True)
class Baseline:
    """Snapshot of a watched directory with optional HMAC-SHA256 signature."""

    version: int
    created_at: str
    root_dir: str
    files: dict[str, FileRecord]
    hmac_sha256: str | None = None


@dataclass(frozen=True)
class IntegrityChange:
    """A single detected integrity violation."""

    path: str
    change_type: str  # modified | permissions_changed | deleted | added
    severity: str  # HIGH | MEDIUM
    detail: str


@dataclass
class IntegrityReport:
    """Result of comparing current filesystem state against a baseline."""

    root_dir: str
    checked_files: int
    signature_status: str  # verified | unsigned | invalid
    changes: list[IntegrityChange] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        return self.signature_status != "invalid" and len(self.changes) == 0
