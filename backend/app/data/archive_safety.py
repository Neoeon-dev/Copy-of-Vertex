"""
Safe Archive Extraction Utilities for VERTEX.
Prevents Zip Slip / Tar Slip (path traversal), symlink attacks, and decompression bombs.
"""
from pathlib import Path
from typing import List, Optional, Union
import os
import tarfile
import zipfile


class ArchiveSecurityError(Exception):
    """Raised when an archive contains dangerous paths, symlinks, or violates limits."""
    pass


def is_safe_path(target_path: Path, base_dir: Path) -> bool:
    """Verifies that target_path resolves strictly within base_dir."""
    try:
        resolved_target = target_path.resolve()
        resolved_base = base_dir.resolve()
        return resolved_target.is_relative_to(resolved_base)
    except (ValueError, RuntimeError):
        return False


def safe_extract_tar(
    archive_path: Union[str, Path],
    dest_dir: Union[str, Path],
    max_files: int = 100_000,
    max_total_bytes: int = 1024 * 1024 * 1024,  # 1 GB
    max_single_file_bytes: int = 50 * 1024 * 1024,  # 50 MB
) -> List[Path]:
    """
    Safely extracts a tar archive (tar, tar.gz, tar.bz2) into dest_dir.
    Rejects path traversals, external symlinks, and oversized contents.
    Returns list of extracted file Paths.
    """
    tar_path = Path(archive_path)
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    resolved_dest = dest.resolve()

    extracted_files: List[Path] = []
    total_bytes = 0
    file_count = 0

    with tarfile.open(tar_path, "r:*") as tar:
        for member in tar.getmembers():
            # 1. Reject absolute paths or paths containing traversal elements
            member_path = Path(member.name)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise ArchiveSecurityError(
                    f"Path traversal detected in archive member: {member.name}"
                )

            target = (dest / member.name).resolve()
            if not target.is_relative_to(resolved_dest):
                raise ArchiveSecurityError(
                    f"Extraction path escapes destination directory: {member.name}"
                )

            # 2. Reject dangerous types: symlinks, hardlinks, FIFOs, devices
            if member.issym() or member.islnk():
                # Verify link target doesn't escape
                link_target = (target.parent / member.linkname).resolve()
                if not link_target.is_relative_to(resolved_dest):
                    raise ArchiveSecurityError(
                        f"Symlink escapes destination directory: {member.name} -> {member.linkname}"
                    )
            elif not (member.isreg() or member.isdir()):
                raise ArchiveSecurityError(
                    f"Unsupported or dangerous member type: {member.name}"
                )

            # 3. Check decompression bomb limits
            if member.isreg():
                file_count += 1
                if file_count > max_files:
                    raise ArchiveSecurityError(
                        f"Archive exceeds maximum file count limit ({max_files})"
                    )
                if member.size > max_single_file_bytes:
                    raise ArchiveSecurityError(
                        f"Member {member.name} exceeds max single file size ({member.size} > {max_single_file_bytes})"
                    )
                total_bytes += member.size
                if total_bytes > max_total_bytes:
                    raise ArchiveSecurityError(
                        f"Archive exceeds total extracted size limit ({total_bytes} > {max_total_bytes})"
                    )

        # Extraction loop after passing all security checks
        for member in tar.getmembers():
            dest_member_path = dest / member.name
            if member.isdir():
                dest_member_path.mkdir(parents=True, exist_ok=True)
            elif member.isreg():
                dest_member_path.parent.mkdir(parents=True, exist_ok=True)
                f_in = tar.extractfile(member)
                if f_in:
                    with open(dest_member_path, "wb") as f_out:
                        while chunk := f_in.read(65536):
                            f_out.write(chunk)
                    extracted_files.append(dest_member_path)

    return extracted_files


def safe_extract_zip(
    archive_path: Union[str, Path],
    dest_dir: Union[str, Path],
    max_files: int = 100_000,
    max_total_bytes: int = 1024 * 1024 * 1024,
    max_single_file_bytes: int = 50 * 1024 * 1024,
) -> List[Path]:
    """
    Safely extracts a zip archive into dest_dir.
    Rejects path traversals and decompression bombs.
    """
    zip_path = Path(archive_path)
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    resolved_dest = dest.resolve()

    extracted_files: List[Path] = []
    total_bytes = 0
    file_count = 0

    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            member_path = Path(info.filename)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise ArchiveSecurityError(
                    f"Path traversal detected in zip member: {info.filename}"
                )

            target = (dest / info.filename).resolve()
            if not target.is_relative_to(resolved_dest):
                raise ArchiveSecurityError(
                    f"Zip extraction path escapes destination directory: {info.filename}"
                )

            if not info.is_dir():
                file_count += 1
                if file_count > max_files:
                    raise ArchiveSecurityError(f"Zip exceeds maximum file count ({max_files})")
                if info.file_size > max_single_file_bytes:
                    raise ArchiveSecurityError(
                        f"Zip member {info.filename} exceeds single file limit"
                    )
                total_bytes += info.file_size
                if total_bytes > max_total_bytes:
                    raise ArchiveSecurityError(
                        f"Zip exceeds total extracted size limit ({total_bytes} > {max_total_bytes})"
                    )

        # Extraction loop
        for info in zf.infolist():
            target = dest / info.filename
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as f_in, open(target, "wb") as f_out:
                    while chunk := f_in.read(65536):
                        f_out.write(chunk)
                extracted_files.append(target)

    return extracted_files
