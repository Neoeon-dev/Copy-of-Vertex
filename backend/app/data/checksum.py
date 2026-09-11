"""
Deterministic SHA-256 Checksum Utilities for VERTEX Dataset Integrity.
Supports single-file hashing, directory trees, manifest generation, and verification.
"""
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional, Union
import hashlib
import json
import os


def calculate_sha256(file_path: Union[str, Path], chunk_size: int = 65536) -> str:
    """Calculates SHA-256 hex digest of a file in streaming chunks."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found for checksum: {path}")
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


def calculate_bytes_sha256(data: bytes) -> str:
    """Calculates SHA-256 hex digest of raw in-memory bytes."""
    return hashlib.sha256(data).hexdigest()


def calculate_directory_checksums(
    directory_path: Union[str, Path],
    extensions: Optional[List[str]] = None,
) -> Dict[str, Dict[str, Any]]:
    """
    Recursively scans a directory and computes SHA-256 for each file.
    Returns relative path -> {sha256, size_bytes}.
    """
    root = Path(directory_path)
    if not root.is_dir():
        raise NotADirectoryError(f"Directory not found: {root}")

    results = {}
    for item in sorted(root.rglob("*")):
        if item.is_file():
            if extensions and item.suffix.lower() not in [e.lower() for e in extensions]:
                continue
            rel_path = str(item.relative_to(root))
            results[rel_path] = {
                "sha256": calculate_sha256(item),
                "size_bytes": item.stat().st_size,
            }
    return results


def generate_checksum_manifest(
    file_paths: List[Union[str, Path]],
    base_dir: Optional[Union[str, Path]] = None,
) -> Dict[str, Any]:
    """Generates a structured manifest mapping relative file paths to checksum and size."""
    entries = {}
    base = Path(base_dir) if base_dir else None
    for p in file_paths:
        path = Path(p)
        if not path.exists():
            continue
        rel_key = str(path.relative_to(base)) if base and path.is_relative_to(base) else str(path)
        entries[rel_key] = {
            "sha256": calculate_sha256(path),
            "size_bytes": path.stat().st_size,
        }
    return {
        "generator": "VERTEX-Checksum-Engine/1.0",
        "file_count": len(entries),
        "files": entries,
    }


def verify_manifest_checksums(
    manifest: Union[str, Path, Dict[str, Any]],
    base_dir: Optional[Union[str, Path]] = None,
) -> Tuple[bool, List[str]]:
    """
    Verifies disk files against a checksum manifest.
    Returns (all_matched: bool, list_of_mismatches_or_missing: List[str]).
    """
    if isinstance(manifest, (str, Path)):
        with open(manifest, "r", encoding="utf-8") as f:
            manifest_data = json.load(f)
    else:
        manifest_data = manifest

    files_dict = manifest_data.get("files", {})
    base = Path(base_dir) if base_dir else Path(".")
    mismatches = []

    for rel_path, meta in files_dict.items():
        expected_sha = meta.get("sha256")
        target_path = base / rel_path
        if not target_path.exists() or not target_path.is_file():
            mismatches.append(f"MISSING: {rel_path} not found on disk")
            continue
        actual_sha = calculate_sha256(target_path)
        if actual_sha != expected_sha:
            mismatches.append(
                f"MISMATCH: {rel_path} expected {expected_sha} but found {actual_sha}"
            )

    return (len(mismatches) == 0, mismatches)
