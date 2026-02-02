"""
Hidden File Finder
------------------

This helper scans a directory (optionally recursively) to find "hidden" files.

Definition of hidden:
    - Cross‑platform: any file or directory whose name starts with a dot (".")
      e.g. ".git", ".env", ".DS_Store".
    - On Windows, we ALSO try to detect the FILE_ATTRIBUTE_HIDDEN flag.

The scanner returns a formatted string that can be displayed directly
in the GUI.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import List


@dataclass
class HiddenFileResult:
    root: str
    paths: List[str]


def _is_hidden_unix(name: str) -> bool:
    """Simple Unix-style hidden check based on filename."""
    return name.startswith(".")


def _is_hidden_windows(full_path: str) -> bool:
    """
    Windows-specific hidden check using file attributes.

    We use the FILE_ATTRIBUTE_HIDDEN flag via ctypes. If anything fails,
    we just fall back to the name-based check.
    """
    try:
        import ctypes

        FILE_ATTRIBUTE_HIDDEN = 0x2
        attrs = ctypes.windll.kernel32.GetFileAttributesW(full_path)
        if attrs == -1:
            return False
        return bool(attrs & FILE_ATTRIBUTE_HIDDEN)
    except Exception:
        # Fallback to name-based detection on any error
        return _is_hidden_unix(os.path.basename(full_path))


def _is_hidden(full_path: str) -> bool:
    """Cross-platform 'hidden' detection."""
    name = os.path.basename(full_path)

    # First, dot-based (works on all platforms)
    if _is_hidden_unix(name):
        return True

    # Extra attribute-based check on Windows
    if os.name == "nt":  # Windows
        return _is_hidden_windows(full_path)

    return False


def find_hidden_files(root_path: str, recursive: bool = True) -> HiddenFileResult:
    """
    Scan a directory and return all hidden files/directories found.

    :param root_path: Directory to scan.
    :param recursive: If True, walk subdirectories; otherwise, only this level.
    """
    hidden: List[str] = []

    if not os.path.isdir(root_path):
        return HiddenFileResult(root=root_path, paths=hidden)

    if recursive:
        for dirpath, dirnames, filenames in os.walk(root_path):
            # Check directories
            for d in dirnames:
                full = os.path.join(dirpath, d)
                if _is_hidden(full):
                    hidden.append(full)
            # Check files
            for f in filenames:
                full = os.path.join(dirpath, f)
                if _is_hidden(full):
                    hidden.append(full)
    else:
        # Only the top-level directory
        with os.scandir(root_path) as it:
            for entry in it:
                if _is_hidden(entry.path):
                    hidden.append(entry.path)

    return HiddenFileResult(root=root_path, paths=hidden)


def format_hidden_results(result: HiddenFileResult) -> str:
    """
    Create a human-readable report string for GUI display.

    The format is intentionally similar to other tools in the project:
    a header, summary section, and a detailed listing.
    """
    root = os.path.abspath(result.root)
    count = len(result.paths)

    header = [
        "Hidden File Finder Results",
        "═══════════════════════════",
        f"Scan root : {root}",
        f"Hidden items found: {count}",
        "",
    ]

    if count == 0:
        header.append("No hidden files or folders were detected in this location.")
        header.append("")
        header.append(
            "Note: Hidden items include names starting with '.' and, on Windows, "
            "entries with the HIDDEN file attribute."
        )
        return "\n".join(header)

    lines = header
    lines.append("Hidden items:")
    lines.append("")

    for p in sorted(result.paths):
        rel = os.path.relpath(p, root)
        lines.append(f"  - {rel}")

    lines.append("")
    lines.append(
        "Tip: Review these files and directories. They may contain configuration, "
        "credentials, or artifacts that should not be exposed."
    )

    return "\n".join(lines)


