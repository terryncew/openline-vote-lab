"""Make a deterministic source archive; no keys, generated elections, caches or Git metadata."""
import gzip
import hashlib
import io
from pathlib import Path
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
PREFIX = f"openline-vote-lab-{VERSION}"
OUTPUT = ROOT / "artifacts" / f"release-{VERSION}"


def main():
    paths = [ROOT / name for name in ("README.md", "LICENSE", ".gitignore", "pyproject.toml", "requirements.lock")]
    for name in ("vote_lab", "tests", "docs", "scripts"):
        paths += [p for p in (ROOT / name).rglob("*") if p.is_file() and "__pycache__" not in p.parts and p.suffix not in (".pyc", ".log")]
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(paths):
            if path.is_symlink():
                raise ValueError(f"Release refuses symlink: {path}")
            data = path.read_bytes()
            info = tarfile.TarInfo(str(Path(PREFIX) / path.relative_to(ROOT)))
            info.size, info.mtime, info.mode = len(data), 0, 0o644
            archive.addfile(info, io.BytesIO(data))
    OUTPUT.mkdir(parents=True, exist_ok=True)
    target = OUTPUT / (PREFIX + ".tar.gz")
    with target.open("wb") as stream:
        with gzip.GzipFile(filename="", fileobj=stream, mode="wb", mtime=0) as compressed:
            compressed.write(buffer.getvalue())
    checksum = hashlib.sha256(target.read_bytes()).hexdigest()
    (OUTPUT / "SHA256SUMS").write_text(f"{checksum}  {target.name}\n")
    print(target.relative_to(ROOT))
    print(f"SHA-256 {checksum}")


if __name__ == "__main__":
    main()
