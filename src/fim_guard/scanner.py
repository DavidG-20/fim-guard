"""Safe recursive directory scanner for file integrity snapshots."""

from pathlib import Path
import stat

from fim_guard.crypto import hash_file_sha256
from fim_guard.models import FileRecord

DEFAULT_IGNORED_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache"}


def scan_directory(
    root_dir: Path,
    exclude_paths: set[Path] | None = None,
    ignored_dirs: set[str] | None = None,
) -> dict[str, FileRecord]:
    """Scan root_dir recursively without following symlinks and hash every regular file."""
    root_resolved = root_dir.resolve()
    excluded = {p.resolve() for p in (exclude_paths or set())}
    skip_dirs = DEFAULT_IGNORED_DIRS | (ignored_dirs or set())
    records: dict[str, FileRecord] = {}

    def _walk(current: Path) -> None:
        for entry in sorted(current.iterdir(), key=lambda p: p.name):
            if entry.is_symlink():
                continue
            resolved = entry.resolve()
            if resolved in excluded:
                continue
            if entry.is_dir():
                if entry.name in skip_dirs:
                    continue
                _walk(entry)
                continue
            if not entry.is_file():
                continue

            rel_path = resolved.relative_to(root_resolved).as_posix()
            st = entry.stat()
            records[rel_path] = FileRecord(
                path=rel_path,
                sha256=hash_file_sha256(entry),
                size=st.st_size,
                mode=oct(stat.S_IMODE(st.st_mode)),
            )

    _walk(root_resolved)
    return records
