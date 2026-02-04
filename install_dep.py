#!/usr/bin/env python3
"""
Dependency installer for the Explorer project.

Downloads and installs third-party dependencies (Frida, SQLite, spdlog, Poco)
into the third_party/ directory. Skips dependencies that are already installed.

Invoked by cmake/Dependencies.cmake at configure time, which passes all
version strings and the target platform via command-line arguments.
Can also be run standalone with explicit arguments.
"""

import argparse
import shutil
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from urllib.request import urlretrieve

SCRIPT_DIR = Path(__file__).resolve().parent
THIRD_PARTY_DIR = SCRIPT_DIR / "third_party"


def download(url: str, dest: Path) -> None:
    print(f"  Downloading {url}")
    urlretrieve(url, dest)


def install_frida(version: str, platform: str) -> None:
    target_dir = THIRD_PARTY_DIR / "frida"
    lib_file = target_dir / "lib" / "libfrida-core.a"
    header_file = target_dir / "include" / "frida-core.h"

    if lib_file.exists() and header_file.exists():
        print("[frida] Already installed, skipping.")
        return

    archive_name = f"frida-core-devkit-{version}-{platform}.tar.xz"
    url = f"https://github.com/frida/frida/releases/download/{version}/{archive_name}"

    print(f"[frida] Installing version {version} ({platform})")
    with tempfile.TemporaryDirectory() as tmp:
        archive_path = Path(tmp) / archive_name
        download(url, archive_path)

        print("  Extracting...")
        with tarfile.open(archive_path, "r:xz") as tar:
            tar.extract("./frida-core.h", path=tmp, filter='data')
            tar.extract("./libfrida-core.a", path=tmp, filter='data')

        lib_file.parent.mkdir(parents=True, exist_ok=True)
        header_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(Path(tmp) / "libfrida-core.a"), str(lib_file))
        shutil.move(str(Path(tmp) / "frida-core.h"), str(header_file))

    print("[frida] Done.")


def install_sqlite(version: str, year: str) -> None:
    target_dir = THIRD_PARTY_DIR / "sqlite"
    src_file = target_dir / "src" / "sqlite3.c"
    header_file = target_dir / "include" / "sqlite3.h"

    if src_file.exists() and header_file.exists():
        print("[sqlite] Already installed, skipping.")
        return

    file_stem = f"sqlite-amalgamation-{version}"
    zip_name = f"{file_stem}.zip"
    url = f"https://sqlite.org/{year}/{zip_name}"

    print(f"[sqlite] Installing version {version}")
    with tempfile.TemporaryDirectory() as tmp:
        archive_path = Path(tmp) / zip_name
        download(url, archive_path)

        print("  Extracting...")
        with zipfile.ZipFile(archive_path) as zf:
            zf.extractall(tmp)

        extracted = Path(tmp) / file_stem
        if not (extracted / "sqlite3.c").exists():
            print("Error: sqlite3.c not found in archive", file=sys.stderr)
            sys.exit(1)

        src_dir = target_dir / "src"
        inc_dir = target_dir / "include"
        src_dir.mkdir(parents=True, exist_ok=True)
        inc_dir.mkdir(parents=True, exist_ok=True)

        shutil.move(str(extracted / "sqlite3.c"), str(src_dir / "sqlite3.c"))
        shutil.move(str(extracted / "sqlite3.h"), str(inc_dir / "sqlite3.h"))
        shutil.move(str(extracted / "sqlite3ext.h"), str(inc_dir / "sqlite3ext.h"))

    print("[sqlite] Done.")


def install_spdlog(version: str) -> None:
    target_dir = THIRD_PARTY_DIR / "spdlog"

    if target_dir.is_dir() and (target_dir / "spdlog.h").exists():
        print("[spdlog] Already installed, skipping.")
        return

    url = f"https://github.com/gabime/spdlog/archive/refs/tags/v{version}.tar.gz"
    archive_name = f"spdlog-{version}.tar.gz"
    extracted_name = f"spdlog-{version}"

    print(f"[spdlog] Installing version {version}")
    with tempfile.TemporaryDirectory() as tmp:
        archive_path = Path(tmp) / archive_name
        download(url, archive_path)

        print("  Extracting...")
        with tarfile.open(archive_path, "r:gz") as tar:
            tar.extractall(path=tmp)

        headers_src = Path(tmp) / extracted_name / "include" / "spdlog"
        if not headers_src.is_dir():
            print("Error: include/spdlog not found in archive", file=sys.stderr)
            sys.exit(1)

        if target_dir.exists():
            shutil.rmtree(target_dir)
        shutil.copytree(str(headers_src), str(target_dir))

    print("[spdlog] Done.")


def install_poco(version: str) -> None:
    target_dir = THIRD_PARTY_DIR / "poco"

    if target_dir.is_dir() and (target_dir / "CMakeLists.txt").exists():
        print("[poco] Already installed, skipping.")
        return

    url = f"https://github.com/pocoproject/poco/archive/refs/tags/poco-{version}-release.zip"
    zip_name = f"poco-{version}-release.zip"
    extracted_name = f"poco-poco-{version}-release"

    print(f"[poco] Installing version {version}")
    with tempfile.TemporaryDirectory() as tmp:
        archive_path = Path(tmp) / zip_name
        download(url, archive_path)

        print("  Extracting...")
        with zipfile.ZipFile(archive_path) as zf:
            zf.extractall(tmp)

        extracted = Path(tmp) / extracted_name
        if not (extracted / "CMakeLists.txt").exists():
            print("Error: CMakeLists.txt not found in extracted Poco archive", file=sys.stderr)
            sys.exit(1)

        if target_dir.exists():
            shutil.rmtree(target_dir)
        shutil.move(str(extracted), str(target_dir))

    print("[poco] Done.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install Explorer third-party dependencies."
    )
    parser.add_argument("--frida-version", required=True)
    parser.add_argument("--frida-platform", required=True,
                        help="Frida platform string, e.g. android-arm")
    parser.add_argument("--sqlite-version", required=True)
    parser.add_argument("--sqlite-year", required=True,
                        help="Year subdirectory on sqlite.org for the download URL")
    parser.add_argument("--spdlog-version", required=True)
    parser.add_argument("--poco-version", required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    print(f"Project root: {SCRIPT_DIR}")
    print(f"Third-party dir: {THIRD_PARTY_DIR}")
    print()

    install_frida(args.frida_version, args.frida_platform)
    install_sqlite(args.sqlite_version, args.sqlite_year)
    install_spdlog(args.spdlog_version)
    install_poco(args.poco_version)

    print()
    print("All dependencies installed successfully.")


if __name__ == "__main__":
    main()
