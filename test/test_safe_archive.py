import io
import os
import tarfile
import zipfile

import pytest
from assemblyline.common import safe_archive
from assemblyline.common.safe_archive import (
    UnsafeArchiveMember,
    safe_extract_tar,
    safe_extract_zip,
    safe_tar_members,
)


def _tar(members):
    """members: list of (name, type, payload_or_linkname)"""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for name, typ, data in members:
            ti = tarfile.TarInfo(name)
            ti.type = typ
            if typ == tarfile.REGTYPE:
                ti.size = len(data)
                t.addfile(ti, io.BytesIO(data))
            else:
                ti.linkname = data
                t.addfile(ti)
    buf.seek(0)
    return buf


def _zip(members):
    """members: list of (name, bytes)"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in members:
            z.writestr(name, data)
    buf.seek(0)
    return buf


# ---------------------------------------------------------------------------
# test safe_extract_tar — exercised on BOTH the PEP 706 path and the fallback
# ---------------------------------------------------------------------------

@pytest.fixture(params=["data_filter", "fallback"], ids=["pep706", "fallback"])
def tar_mode(request, monkeypatch):
    if request.param == "fallback":
        # Force the safe_tar_members fallback as if running on < 3.11.4.
        monkeypatch.delattr(safe_archive.tarfile, "data_filter", raising=False)
    return request.param


def test_tar_extracts_regular_files(tar_mode, tmp_path):
    buf = _tar([
        ("a.txt", tarfile.REGTYPE, b"hello"),
        ("sub/b.txt", tarfile.REGTYPE, b"world"),
    ])
    with tarfile.open(fileobj=buf) as t:
        safe_extract_tar(t, str(tmp_path))
    assert (tmp_path / "a.txt").read_bytes() == b"hello"
    assert (tmp_path / "sub" / "b.txt").read_bytes() == b"world"


@pytest.mark.parametrize(
    "name,typ,target",
    [
        ("escape", tarfile.SYMTYPE, "/etc/hosts"),
        ("escape", tarfile.SYMTYPE, "../../../../etc/hosts"),
        ("escape", tarfile.LNKTYPE, "/etc/hosts"),
    ],
    ids=["sym-abs", "sym-dotdot", "hardlink-abs"],
)
def test_tar_drops_or_rejects_escaping_links(tar_mode, tmp_path, name, typ, target):
    buf = _tar([
        ("ok.txt", tarfile.REGTYPE, b"ok"),
        (name, typ, target),
    ])
    with tarfile.open(fileobj=buf) as t:
        if tar_mode == "data_filter":
            with pytest.raises(tarfile.FilterError):
                safe_extract_tar(t, str(tmp_path))
        else:
            safe_extract_tar(t, str(tmp_path))
            assert (tmp_path / "ok.txt").exists()
            assert not (tmp_path / name).exists()


def test_tar_drops_dotdot_member_name(tar_mode, tmp_path):
    buf = _tar([
        ("ok.txt", tarfile.REGTYPE, b"ok"),
        ("../escape.txt", tarfile.REGTYPE, b"x"),
    ])
    parent_sentinel = tmp_path.parent / "escape.txt"
    with tarfile.open(fileobj=buf) as t:
        if tar_mode == "data_filter":
            with pytest.raises(tarfile.FilterError):
                safe_extract_tar(t, str(tmp_path))
        else:
            safe_extract_tar(t, str(tmp_path))
            assert (tmp_path / "ok.txt").exists()
    assert not parent_sentinel.exists()


def test_tar_accepts_path_argument(tar_mode, tmp_path):
    p = tmp_path / "a.tgz"
    p.write_bytes(_tar([("x", tarfile.REGTYPE, b"y")]).getvalue())
    out = tmp_path / "out"
    out.mkdir()
    safe_extract_tar(str(p), str(out))
    assert (out / "x").read_bytes() == b"y"


def test_safe_tar_members_filters_only_offenders(tmp_path):
    buf = _tar([
        ("ok.txt", tarfile.REGTYPE, b"ok"),
        ("../bad.txt", tarfile.REGTYPE, b"x"),
        ("link", tarfile.SYMTYPE, "/etc/hosts"),
        ("inlink", tarfile.SYMTYPE, "ok.txt"),
    ])
    with tarfile.open(fileobj=buf) as t:
        names = {m.name for m in safe_tar_members(t, str(tmp_path))}
    assert names == {"ok.txt", "inlink"}


# ---------------------------------------------------------------------------
# test safe_extract_zip
# ---------------------------------------------------------------------------

def test_zip_extracts_regular_files(tmp_path):
    buf = _zip([("a.txt", b"hello"), ("sub/b.txt", b"world")])
    with zipfile.ZipFile(buf) as z:
        safe_extract_zip(z, str(tmp_path))
    assert (tmp_path / "a.txt").read_bytes() == b"hello"
    assert (tmp_path / "sub" / "b.txt").read_bytes() == b"world"


@pytest.mark.parametrize("bad", ["../escape.txt", "../../etc/passwd"])
def test_zip_rejects_dotdot_member(tmp_path, bad):
    buf = _zip([("ok.txt", b"ok"), (bad, b"x")])
    with zipfile.ZipFile(buf) as z:
        with pytest.raises(UnsafeArchiveMember):
            safe_extract_zip(z, str(tmp_path))
    assert not (tmp_path.parent / "escape.txt").exists()


def test_zip_rejects_traversal_through_existing_symlink(tmp_path):
    # Pre-existing symlink in the destination — ZipFile.extractall alone
    # would happily write through it:
    # tmp_path/
    # ├── outside/                 ← directory we should never touch
    # └── dest/
    #     └── evil -> ../outside   ← pre-existing symlink (NOT from this zip)
    outside = tmp_path / "outside"
    outside.mkdir()
    dest = tmp_path / "dest"
    dest.mkdir()
    os.symlink(outside, dest / "evil")

    buf = _zip([("evil/payload.txt", b"pwned")])
    with zipfile.ZipFile(buf) as z:
        with pytest.raises(UnsafeArchiveMember):
            safe_extract_zip(z, str(dest))
    assert not (outside / "payload.txt").exists()


@pytest.mark.parametrize("bad", ["../escape.txt", "/abs.txt"])
def test_zip_skip_mode_drops_offenders(tmp_path, bad):
    buf = _zip([("ok.txt", b"ok"), (bad, b"x")])
    with zipfile.ZipFile(buf) as z:
        safe_extract_zip(z, str(tmp_path), on_unsafe="skip")
    assert (tmp_path / "ok.txt").read_bytes() == b"ok"
    assert set(p.name for p in tmp_path.iterdir()) == {"ok.txt"}


def test_zip_accepts_path_argument(tmp_path):
    p = tmp_path / "a.zip"
    p.write_bytes(_zip([("x", b"y")]).getvalue())
    out = tmp_path / "out"
    out.mkdir()
    safe_extract_zip(str(p), str(out))
    assert (out / "x").read_bytes() == b"y"


def test_zip_invalid_on_unsafe_value(tmp_path):
    buf = _zip([("a", b"b")])
    with zipfile.ZipFile(buf) as z:
        with pytest.raises(ValueError):
            safe_extract_zip(z, str(tmp_path), on_unsafe="ignore")
