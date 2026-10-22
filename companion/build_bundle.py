"""
Deterministic Windows Bundle Builder for PacketSentinel.
Packages PacketSentinel into a standalone Windows executable bundle (dist/PacketSentinel/)
and generates SHA-256 integrity checksums (SHA256SUMS.txt) for GitHub Releases (OWASP #44, #45).
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def build_bundle(onefile: bool = False) -> int:
    repo_root = Path(__file__).resolve().parent
    entrypoint = repo_root / "run_packetsentinel.py"
    dist_dir = repo_root / "dist"
    build_dir = repo_root / "build"

    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print(
            "[!] PyInstaller is not installed in the current Python environment.\n"
            "    Install it with: python -m pip install pyinstaller\n"
            "    Then re-run:     python build_bundle.py",
            file=sys.stderr,
        )
        return 1

    if dist_dir.exists():
        shutil.rmtree(dist_dir)
    if build_dir.exists():
        shutil.rmtree(build_dir)

    mode_flag = "--onefile" if onefile else "--onedir"
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        mode_flag,
        "--name",
        "PacketSentinel",
        "--console",
        str(entrypoint),
    ]

    print(f"[*] Building Windows bundle ({mode_flag}) via PyInstaller...")
    res = subprocess.run(cmd, cwd=str(repo_root), shell=False, check=False)
    if res.returncode != 0:
        print("[!] PyInstaller build failed.", file=sys.stderr)
        return res.returncode

    # Create portable zip archive for GitHub Releases
    zip_path = dist_dir / "PacketSentinel-Windows-x64.zip"
    target_path = dist_dir / ("PacketSentinel.exe" if onefile else "PacketSentinel")

    print(f"[*] Creating release archive: {zip_path}")
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        if target_path.is_file():
            zf.write(target_path, arcname=target_path.name)
        else:
            for file_path in sorted(target_path.rglob("*")):
                if file_path.is_file():
                    rel = file_path.relative_to(dist_dir)
                    zf.write(file_path, arcname=str(rel))
        for doc_name in (
            "README.md",
            "SETUP_AND_TROUBLESHOOTING.md",
            "LICENSE",
            "SECURITY.md",
            "Start-PacketSentinel.bat",
        ):
            doc_path = repo_root / doc_name
            if doc_path.is_file():
                zf.write(doc_path, arcname=f"PacketSentinel/{doc_name}")

    # Generate SHA256SUMS.txt
    checksum_lines: list[str] = []
    if zip_path.is_file():
        checksum_lines.append(f"{sha256_file(zip_path)}  {zip_path.name}")
    exe_file = dist_dir / "PacketSentinel.exe" if onefile else dist_dir / "PacketSentinel" / "PacketSentinel.exe"
    if exe_file.is_file():
        checksum_lines.append(f"{sha256_file(exe_file)}  {exe_file.relative_to(dist_dir)}")

    sums_path = dist_dir / "SHA256SUMS.txt"
    sums_path.write_text("\n".join(checksum_lines) + "\n", encoding="utf-8")

    print("[+] Bundle complete!")
    print(f"    Executable : {exe_file}")
    print(f"    Release Zip: {zip_path}")
    print(f"    Checksums  : {sums_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Build standalone Windows bundle for PacketSentinel.")
    parser.add_argument(
        "--onefile",
        action="store_true",
        help="Build a single-file .exe instead of the default --onedir directory bundle.",
    )
    args = parser.parse_args()
    return build_bundle(onefile=bool(args.onefile))


if __name__ == "__main__":
    sys.exit(main())
