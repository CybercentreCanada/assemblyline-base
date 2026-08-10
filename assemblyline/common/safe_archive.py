"""
Safe extraction helpers for tar and zip archives.

Centralises the path-traversal hardening. All Assemblyline components
that extract archives whose contents are not fully trusted should use
these helpers instead of calling
`TarFile.extractall` / `ZipFile.extractall` directly.
"""
import os
import tarfile
import zipfile
from typing import Iterator, Optional, Union


class UnsafeArchiveMember(Exception):
    """Raised when an archive member would escape the destination directory."""


def _is_within(path: str, base: str) -> bool:
    real = os.path.realpath(path)
    return real == base or os.path.commonpath([real, base]) == base


def safe_tar_members(tar: tarfile.TarFile, dest: str) -> Iterator[tarfile.TarInfo]:
    """Yield only members that resolve under *dest* and are not links that escape it.

    This is the fallback used when running on a Python without PEP 706
    (`tarfile.data_filter`, backported to 3.8.17 / 3.9.17 / 3.10.12 / 3.11.4).
    """
    base = os.path.realpath(dest)
    for member in tar.getmembers():
        member_path = os.path.join(base, member.name)
        if not _is_within(member_path, base):
            continue
        if member.issym() or member.islnk():
            link_target = os.path.join(base, os.path.dirname(member.name), member.linkname)
            if not _is_within(link_target, base):
                continue
        yield member


def safe_extract_tar(tar: Union[str, tarfile.TarFile], dest: str) -> None:
    """Extract *tar* into *dest* without allowing members to escape *dest*.

    Prefers PEP 706's `filter='data'` (rejects absolute paths, ``..`` escapes,
    symlinks and hardlinks, device nodes, and strips set[ug]id bits). On older
    interpreters falls back to :func:`safe_tar_members`, which silently drops
    offending members instead of raising.
    """
    owns = isinstance(tar, str)
    tf = tarfile.open(tar) if owns else tar
    try:
        if hasattr(tarfile, "data_filter"):
            tf.extractall(dest, filter="data")
        else:
            tf.extractall(dest, members=list(safe_tar_members(tf, dest)))
    finally:
        if owns:
            tf.close()


def safe_extract_zip(
    zf: Union[str, zipfile.ZipFile],
    dest: str,
    *,
    pwd: Optional[bytes] = None,
    on_unsafe: str = "raise",
) -> None:
    """Extract *zf* into *dest* without allowing members to escape *dest*.

    ``ZipFile.extractall`` already strips leading ``/`` and ``..`` components
    from member names, but it does **not** defend against the destination
    containing pre-existing symlinks (e.g. when re-extracting over a directory
    a previous archive populated). This helper validates each target with
    ``realpath`` before any write occurs.

    :param on_unsafe: ``"raise"`` (default) to raise :class:`UnsafeArchiveMember`
        on the first offending entry, or ``"skip"`` to silently drop it.
    """
    if on_unsafe not in ("raise", "skip"):
        raise ValueError("on_unsafe must be 'raise' or 'skip'")

    owns = isinstance(zf, str)
    zfile = zipfile.ZipFile(zf, "r") if owns else zf
    try:
        base = os.path.realpath(dest)
        safe = []
        for info in zfile.infolist():
            target = os.path.join(base, info.filename)
            if not _is_within(target, base):
                if on_unsafe == "raise":
                    raise UnsafeArchiveMember(
                        f"Path traversal detected in zip member: {info.filename!r}"
                    )
                continue
            safe.append(info)
        zfile.extractall(path=dest, members=safe, pwd=pwd)
    finally:
        if owns:
            zfile.close()
